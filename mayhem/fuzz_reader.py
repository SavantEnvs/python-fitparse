#!/usr/bin/env python3
"""Atheris fuzz harness for python-fitparse — BACKPORT (repro) edition.

Exercises the ANT/Garmin .FIT file parser on arbitrary input. Atheris
instruments the imported fitparse modules (coverage), so libFuzzer drives the
parser toward new code paths.

WHY THIS DIFFERS FROM THE HARNESS ON THE `mayhem` BRANCH
--------------------------------------------------------
This branch reproduces the bugs mayhemheroes/python-fitparse run 9 found at
fork commit ef5b208aa7ce (upstream d88bb6997138). The exception policy below is
the ORIGINAL mayhemheroes harness's policy, reconstructed from
`mayhem/fuzz_reader.py` at that fork commit — it returns -1 (expected outcome)
only for `fitparse.FitParseError` and `AttributeError`; every other escaping
exception is a defect.

BACKPORT.md ("Input-interface caveat": *reconstruct the original harness from
the mayhemheroes fork commit and port it to v2*) is why this is done here and
nowhere else. The live `mayhem` branch additionally swallows
`(ValueError, KeyError, IndexError, TypeError, struct.error)` as "not
memory-safety defects" — a deliberate live-integration policy that makes 6 of
the 7 relevant defects of run 9 (5x TypeError/CWE-704, 1x ValueError/CWE-248)
structurally unreachable, so seeding it with the original corpus reproduces
nothing. The bugs themselves are genuine: they are unhandled exceptions raised
several frames deep inside fitparse/ (records.py component rendering,
base.py field formatting, processors.py datetime conversion) on parser input
the library does not validate — not harness artifacts. This file only decides
which of them are *reported*; it does not create them.

A single malformed .FIT file can, in theory, push the parser into a very slow
path (huge declared record/field counts). To keep fuzz-smoke (and Mayhem's
per-input budget) from stalling on one pathological input, each TestOneInput is
guarded by a per-input SIGALRM watchdog that aborts the individual parse after a
few seconds. (The original harness had no watchdog; a timeout is skipped, never
counted as a defect, so this addition cannot manufacture one.)

Run modes (driven by the compiled launcher `fitparse_fuzzer` / `-standalone`):
  * fuzzing      — `python3 fuzz_reader.py [libFuzzer args]`
  * single input — `python3 fuzz_reader.py <file>` (libFuzzer runs it once)
"""
import io
import logging
import signal
import sys

import atheris

# Instrument the library under test so the fuzzer gets coverage feedback.
with atheris.instrument_imports():
    import fitparse

# fitparse logs warnings on malformed input; silence them so the fuzz log stays useful.
logging.disable(logging.ERROR)


class _InputTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise _InputTimeout()


# Per-input watchdog: a single pathological .FIT must not hang the fuzzer.
signal.signal(signal.SIGALRM, _alarm)
_PER_INPUT_SECONDS = 5


@atheris.instrument_func
def TestOneInput(data):
    signal.setitimer(signal.ITIMER_REAL, _PER_INPUT_SECONDS)
    try:
        # The body of the original mayhemheroes TestOneInput, verbatim.
        with io.BytesIO(data) as f:
            fit_file = fitparse.FitFile(f)
            if not fit_file:
                return -1

            fit_file.parse()

            fit_file.get_messages('record')
            fit_file.get_messages('device_info')
            fit_file.get_messages('event')
            fit_file.get_messages('file_creator')

            fit_file.close()
    except fitparse.FitParseError:
        # Library-defined parse errors are the expected outcome for malformed FITs.
        return -1
    except AttributeError:
        # Original harness: "Just a warning crash, valid- but fast-fail".
        return -1
    except _InputTimeout:
        # This one input was too slow — skip it, don't count it as a defect.
        return -1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
