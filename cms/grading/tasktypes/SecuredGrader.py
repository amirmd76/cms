#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Contest Management System - http://cms-dev.github.io/
# Copyright © 2010-2015 Giovanni Mascellani <mascellani@poisson.phc.unipi.it>
# Copyright © 2010-2014 Stefano Maggiolo <s.maggiolo@gmail.com>
# Copyright © 2010-2012 Matteo Boscariol <boscarim@hotmail.com>
# Copyright © 2012-2014 Luca Wehrstedt <luca.wehrstedt@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os
import tempfile

from cms import LANGUAGES, LANGUAGE_TO_SOURCE_EXT_MAP, \
    LANGUAGE_TO_HEADER_EXT_MAP, LANGUAGE_TO_OBJ_EXT_MAP, config
from cms.grading.Sandbox import wait_without_std
from cms.grading import get_compilation_commands, get_evaluation_commands, \
    compilation_step, evaluation_step, human_evaluation_message, \
    is_evaluation_passed, extract_outcome_and_text, white_diff_step, evaluation_step_before_run, \
    evaluation_step_after_run
from cms.grading.ParameterTypes import ParameterTypeCollection, \
    ParameterTypeChoice, ParameterTypeString
from cms.grading.TaskType import TaskType, \
    create_sandbox, delete_sandbox
from cms.db import Executable
from cms.io.GeventUtils import rmtree

logger = logging.getLogger(__name__)


# Dummy function to mark translatable string.
def N_(message):
    return message


class SecuredGrader(TaskType):
    """Task type class for a unique standalone submission source, with
    comparator (or not).

    Parameters needs to be a list of three elements.

    The first element is 'grader' or 'alone': in the first
    case, the source file is to be compiled with a provided piece of
    software ('grader'); in the other by itself.

    The second element is a 2-tuple of the input file name and output file
    name. The input file may be '' to denote stdin, and similarly the
    output filename may be '' to denote stdout.

    The third element is 'diff' or 'comparator' and says whether the
    output is compared with a simple diff algorithm or using a
    comparator.

    Note: the first element is used only in the compilation step; the
    others only in the evaluation step.

    A comparator can read argv[1], argv[2], argv[3] (respectively,
    input, correct output and user output) and should write the
    outcome to stdout and the text to stderr.

    """
    ALLOW_PARTIAL_SUBMISSION = False


    _EVALUATION = ParameterTypeChoice(
        "Output evaluation",
        "output_eval",
        "",
        {"diff": "Outputs compared with white diff",
         "comparator": "Outputs are compared by a comparator"})

    ACCEPTED_PARAMETERS = [_EVALUATION, ]

    @property
    def name(self):
        """See TaskType.name."""
        # TODO add some details if a grader/comparator is used, etc...
        return "SecuredGraderss"

    def get_compilation_commands(self, submission_format):
        """See TaskType.get_compilation_commands."""
        res = dict()
        for language in LANGUAGES:
            format_filename = submission_format[0]
            source_ext = LANGUAGE_TO_SOURCE_EXT_MAP[language]
            source_filenames = []
            source_filenames.append("grader%s" % source_ext)
            source_filenames.append(format_filename.replace(".%l", source_ext))
            executable_filename = format_filename.replace(".%l", "")
            commands = get_compilation_commands(language,
                                                source_filenames,
                                                executable_filename)
            res[language] = commands
        return res

    def get_user_managers(self, unused_submission_format):
        """See TaskType.get_user_managers."""
        return []

    def get_auto_managers(self):
        """See TaskType.get_auto_managers."""
        return None

    def compile(self, job, file_cacher):
        """See TaskType.compile."""
        # Detect the submission's language. The checks about the
        # formal correctedness of the submission are done in CWS,
        # before accepting it.
        language = job.language
        source_ext = LANGUAGE_TO_SOURCE_EXT_MAP[language]

        # TODO: here we are sure that submission.files are the same as
        # task.submission_format. The following check shouldn't be
        # here, but in the definition of the task, since this actually
        # checks that task's task type and submission format agree.
        if len(job.files) != 1:
            job.success = True
            job.compilation_success = False
            job.text = [N_("Invalid files in submission")]
            logger.error("Submission contains %d files, expecting 1",
                         len(job.files), extra={"operation": job.info})
            return True

        # Create the sandbox
        sandbox = create_sandbox(file_cacher)
        job.sandboxes.append(sandbox.path)

        # Prepare the source files in the sandbox
        files_to_get = {}
        format_filename = job.files.keys()[0]
        source_filenames = []
        source_filenames.append(format_filename.replace(".%l", source_ext))
        files_to_get[source_filenames[0]] = \
            job.files[format_filename].digest

        source_filenames.insert(0, "grader%s" % source_ext)
        files_to_get["grader%s" % source_ext] = \
            job.managers["grader%s" % source_ext].digest

        # Also copy all managers that might be useful during compilation.
        for filename in job.managers.iterkeys():
            if any(filename.endswith(header)
                   for header in LANGUAGE_TO_HEADER_EXT_MAP.itervalues()):
                files_to_get[filename] = \
                    job.managers[filename].digest
            elif any(filename.endswith(source)
                     for source in LANGUAGE_TO_SOURCE_EXT_MAP.itervalues()):
                files_to_get[filename] = \
                    job.managers[filename].digest
            elif any(filename.endswith(obj)
                     for obj in LANGUAGE_TO_OBJ_EXT_MAP.itervalues()):
                files_to_get[filename] = \
                    job.managers[filename].digest

        for filename, digest in files_to_get.iteritems():
            sandbox.create_file_from_storage(filename, digest)

        # Prepare the compilation command
        executable_filename = format_filename.replace(".%l", "")
        commands = get_compilation_commands(language,
                                            source_filenames,
                                            executable_filename)

        # Run the compilation
        operation_success, compilation_success, text, plus = \
            compilation_step(sandbox, commands)

        # Retrieve the compiled executables
        job.success = operation_success
        job.compilation_success = compilation_success
        job.plus = plus
        job.text = text
        if operation_success and compilation_success:
            digest = sandbox.get_file_to_storage(
                executable_filename,
                "Executable %s for %s" %
                (executable_filename, job.info))
            job.executables[executable_filename] = \
                Executable(executable_filename, digest)

        # Cleanup
        delete_sandbox(sandbox)

    def evaluate(self, job, file_cacher):
        """See TaskType.evaluate."""
        # Create sandboxes and FIFOs
        sandbox_mgr = create_sandbox(file_cacher)
        sandbox_user = create_sandbox(file_cacher)
        fifo_dir = tempfile.mkdtemp(dir=config.temp_dir)
        fifo_in = os.path.join(fifo_dir, "in")
        fifo_out = os.path.join(fifo_dir, "out")
        os.mkfifo(fifo_in)
        os.mkfifo(fifo_out)
        os.chmod(fifo_dir, 0o755)
        os.chmod(fifo_in, 0o666)
        os.chmod(fifo_out, 0o666)
        import stat
        def permissions_to_unix_name(st):
            is_dir = 'd' if stat.S_ISDIR(st.st_mode) else '-'
            dic = {'7':'rwx', '6' :'rw-', '5' : 'r-x', '4':'r--', '0': '---'}
            perm = str(oct(st.st_mode)[-3:])
            return is_dir + ''.join(dic.get(x,x) for x in perm)
        logger.warning(permissions_to_unix_name(os.stat(fifo_out)))
        logger.warning(fifo_out)
        input_filename = "input.txt"
        output_filename = "output.txt"

        # First step: we start the oracle.
        oracle_filename = "oracle"
        oracle_command = ["./%s" % oracle_filename, fifo_in, fifo_out]
        oracle_executables_to_get = {
            oracle_filename:
            job.managers[oracle_filename].digest
        }
        oracle_files_to_get = {
            input_filename: job.input
        }
        oracle_allow_dirs = [fifo_dir]
        for filename, digest in oracle_executables_to_get.iteritems():
            sandbox_mgr.create_file_from_storage(
                filename, digest, executable=True)
        for filename, digest in oracle_files_to_get.iteritems():
            sandbox_mgr.create_file_from_storage(filename, digest)
        oracle = evaluation_step_before_run(
            sandbox_mgr,
            oracle_command,
            job.time_limit,
            0,
            allow_dirs=oracle_allow_dirs,
            stdin_redirect=input_filename,
            stdout_redirect=output_filename)

        # Prepare the execution
        executable_filename = job.executables.keys()[0]
        command = ["./%s" % executable_filename, fifo_out, fifo_in]
        executables_to_get = {
            executable_filename:
            job.executables[executable_filename].digest
        }

        user_allow_dirs = [fifo_dir]
        # Put the required files into the sandbox
        for filename, digest in executables_to_get.iteritems():
            sandbox_user.create_file_from_storage(filename, digest, executable=True)


        # Actually performs the execution
        user = evaluation_step_before_run(
            sandbox_user,
            command,
            job.time_limit,
            job.memory_limit,
            allow_dirs=user_allow_dirs,)

        # Consume output.
        wait_without_std([user, oracle])
        # TODO: check exit codes with translate_box_exitcode.
        logger.warning("I am here")
        success_user, plus_user = \
            evaluation_step_after_run(sandbox_user)
        logger.warning("I am here too")
        success_mgr, unused_plus_mgr = \
            evaluation_step_after_run(sandbox_mgr)

        job.sandboxes = [sandbox_user.path,
                         sandbox_mgr.path]
        job.plus = plus_user

        outcome = None
        text = None

        # If at least one evaluation had problems, we report the
        # problems.
        if not success_mgr:
            success, text = False, "MGR"
        if not success_user:
            success, text = False, "USR"

        # If the user sandbox detected some problem (timeout, ...),
        # the outcome is 0.0 and the text describes that problem.
        elif not is_evaluation_passed(plus_user):
            success = True
            outcome = 0.0
            text = human_evaluation_message(plus_user)
            if job.get_output:
                job.user_output = None

        # Otherwise, advance to checking the solution
        else:
            success = True
            # Check that the output file was created
            if not sandbox_mgr.file_exists(output_filename):
                success = False
                outcome = 0.0
                text = [N_("Evaluation didn't produce output file")]
                if job.get_output:
                    job.user_output = None

            else:
                # If asked so, put the output file into the storage
                if job.get_output:
                    job.user_output = sandbox_mgr.get_file_to_storage(
                        output_filename,
                        "Output file in job %s" % job.info,
                        trunc_len=100 * 1024)

                # If just asked to execute, fill text and set dummy
                # outcome.
                if job.only_execution:
                    outcome = 0.0
                    text = [N_("Execution completed successfully")]

                # Otherwise evaluate the output file.
                else:

                    # Put the reference solution into the sandbox
                    sandbox_mgr.create_file_from_storage(
                        "res.txt",
                        job.output)

                    # Check the solution with white_diff
                    if self.parameters[0] == "diff":
                        outcome, text = white_diff_step(
                            sandbox_mgr, output_filename, "res.txt")

                    # Check the solution with a comparator
                    elif self.parameters[0] == "comparator":
                        manager_filename = "checker"

                        if manager_filename not in job.managers:
                            logger.error("Configuration error: missing or "
                                         "invalid comparator (it must be "
                                         "named 'checker')",
                                         extra={"operation": job.info})
                            success = False

                        else:
                            sandbox_mgr.create_file_from_storage(
                                manager_filename,
                                job.managers[manager_filename].digest,
                                executable=True)
                            # Rewrite input file. The untrusted
                            # contestant program should not be able to
                            # modify it; however, the grader may
                            # destroy the input file to prevent the
                            # contestant's program from directly
                            # accessing it. Since we cannot create
                            # files already existing in the sandbox,
                            # we try removing the file first.
                            try:
                                sandbox_mgr.remove_file(input_filename)
                            except OSError as e:
                                # Let us be extra sure that the file
                                # was actually removed and we did not
                                # mess up with permissions.
                                assert not sandbox_mgr.file_exists(input_filename)
                            sandbox_mgr.create_file_from_storage(
                                input_filename,
                                job.input)
                            success, _ = evaluation_step(
                                sandbox_mgr,
                                [["./%s" % manager_filename,
                                  input_filename, "res.txt", output_filename]])
                        if success:
                            try:
                                outcome, text = \
                                    extract_outcome_and_text(sandbox_mgr)
                            except ValueError, e:
                                logger.error("Invalid output from "
                                             "comparator: %s", e.message,
                                             extra={"operation": job.info})
                                success = False

                    else:
                        raise ValueError("Unrecognized third parameter"
                                         " `%s' for SecuredGrader tasktype." %
                                         self.parameters[0])

        # Whatever happened, we conclude.
        job.success = success
        job.outcome = "%s" % outcome if outcome is not None else None
        job.text = text

        delete_sandbox(sandbox_mgr)
        delete_sandbox(sandbox_user)
        if not config.keep_sandbox:
            rmtree(fifo_dir)
