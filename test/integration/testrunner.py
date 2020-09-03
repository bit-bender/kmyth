#!/usr/bin/python3

import pathlib
import argparse
import signal
import sys
import glob
import subprocess
import atexit
import time
import re

# Global Test Path Parameters
INTEGRATION_TEST_ROOT = pathlib.Path(sys.path[0])
KEY_SERVER_SCRIPT_PATH = INTEGRATION_TEST_ROOT / 'sampleTestServer.py'
KMYTH_BIN_PATH = INTEGRATION_TEST_ROOT.parent.parent / 'bin'
UNSEALED_KEY_PATH = INTEGRATION_TEST_ROOT / 'key' / 'client.key'
SEALED_KEY_PATH = INTEGRATION_TEST_ROOT / 'ski' / 'client.ski'
UNSEAL_RESULT_PATH = INTEGRATION_TEST_ROOT / 'out' / 'client.key.out'
OUTPUT_KEYFILE_PATH = INTEGRATION_TEST_ROOT / 'key' / 'kmyth-kek.key'
KEY_SERVER_CERT_PATH = INTEGRATION_TEST_ROOT / 'cert' / 'server.pem'
CLIENT_CERT_PATH = INTEGRATION_TEST_ROOT / 'cert' / 'client.pem'
TEST_KEY_PATH = INTEGRATION_TEST_ROOT / 'key' / 'test.key'

# Global Test Command line Parameters
AUTH_STRING = 'password'
WRONG_AUTH_STRING = 'wrongPassword'
PCR_SELECTION = '"0, 1, 2, 3"'
WRONG_PCR_SELECTION = '"0, 4"'
KEY_SERVER_ADDRESS = '127.0.0.1:54321'

#-----------------------------------------------------------------------------
# Integration Test - Test Definitions
#-----------------------------------------------------------------------------

"""
Test Kmyth Applications with Default Policy
  - no authorization string
  - no PCR criteria
"""
DEFAULT_POLICY_TEST = {'title':'Default Authorization Policy Test',
                       'seq':[{'desc':'kmyth-seal specifying empty (default) policy',
                               'args':[KMYTH_BIN_PATH / 'kmyth-seal',
                                       '-i', UNSEALED_KEY_PATH,
                                       '-o', SEALED_KEY_PATH,
                                       '-f'],
                               'expect':'PASS'},
                              {'desc':'kmyth-unseal using default criteria for object with default policy',
                               'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                       '-i', SEALED_KEY_PATH,
                                       '-o', UNSEAL_RESULT_PATH,
                                       '-f'],
                               'expect':'PASS'},
                              {'desc':'kmyth-unseal using default criteria - result verification',
                                      'args':['diff',
                                              UNSEAL_RESULT_PATH, UNSEALED_KEY_PATH],
                                      'expect':'PASS'},
                              {'desc':'kmyth-unseal using empty auth string for object with default policy',
                               'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                       '-i', SEALED_KEY_PATH,
                                       '-a', '""',
                                       '-s'],
                               'expect':'FAIL'},
                              {'desc':'kmyth-unseal using empty PCR list for object with default policy',
                               'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                       '-i', SEALED_KEY_PATH,
                                       '-p', '""',
                                       '-s'],
                               'expect':'FAIL'},
                              {'desc':'kmyth-getkey using default criteria for object with default policy',
                               'args':[KMYTH_BIN_PATH / 'kmyth-getkey',
                                       '-i', SEALED_KEY_PATH,
                                       '-l', CLIENT_CERT_PATH,
                                       '-s', KEY_SERVER_CERT_PATH,
                                       '-c', KEY_SERVER_ADDRESS,
                                       '-o', OUTPUT_KEYFILE_PATH],
                               'expect':'PASS'},
                              {'desc':'kmyth-getkey using default criteria - received key verification',
                                      'args':['diff',
                                              OUTPUT_KEYFILE_PATH, TEST_KEY_PATH],
                                      'expect':'PASS'}]}


"""
Test Kmyth Applications with PCR Criteria Only Policy
  - no authorization string
  - PCR criteria
"""
PCR_ONLY_POLICY_TEST = {'title':'PCR Criteria Only Authorization Policy Test',
                        'seq':[{'desc':'kmyth-seal, PCR-only policy',
                                'args':[KMYTH_BIN_PATH / 'kmyth-seal',
                                        '-i', UNSEALED_KEY_PATH,
                                        '-o', SEALED_KEY_PATH,
                                        '-p', PCR_SELECTION,
                                        '-f'],
                                'expect':'PASS'},
                               {'desc':'kmyth-unseal, PCR-only policy',
                                'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                        '-i', SEALED_KEY_PATH,
                                        '-o', UNSEAL_RESULT_PATH,
                                        '-f'],
                                'expect':'PASS'},
                               {'desc':'kmyth-unseal, PCR-only policy - result verification',
                                       'args':['diff',
                                               UNSEAL_RESULT_PATH, UNSEALED_KEY_PATH],
                                       'expect':'PASS'},
                               {'desc':'kmyth-getkey, PCR only policy',
                                'args':[KMYTH_BIN_PATH / 'kmyth-getkey',
                                        '-i', SEALED_KEY_PATH,
                                        '-l', CLIENT_CERT_PATH,
                                        '-s', KEY_SERVER_CERT_PATH,
                                        '-c', KEY_SERVER_ADDRESS,
                                        '-o', OUTPUT_KEYFILE_PATH],
                                'expect':'PASS'},
                               {'desc':'kmyth-getkey, PCR only policy - received key verification',
                                       'args':['diff',
                                               OUTPUT_KEYFILE_PATH, TEST_KEY_PATH],
                                'expect':'PASS'}]}


"""
Test Kmyth Applications with Authorization String Only Policy
  - non-empty authorization string
  - no PCR criteria
"""
AUTHSTRING_ONLY_POLICY_TEST = {'title':'Authorization String Criteria Only Authorization Policy Test',
                               'seq':[{'desc':'kmyth-seal, authorization string policy',
                                       'args':[KMYTH_BIN_PATH / 'kmyth-seal',
                                               '-i', UNSEALED_KEY_PATH,
                                               '-o', SEALED_KEY_PATH,
                                               '-a', AUTH_STRING,
                                               '-f'],
                                       'expect':'PASS'},
                                      {'desc':'kmyth-unseal, correct criteria for object with auth string only policy',
                                       'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                               '-i', SEALED_KEY_PATH,
                                               '-o', UNSEAL_RESULT_PATH,
                                               '-a', AUTH_STRING,
                                               '-f'],
                                       'expect':'PASS'},
                                      {'desc':'kmyth-unseal, auth string only policy - result verification',
                                       'args':['diff',
                                              UNSEAL_RESULT_PATH, UNSEALED_KEY_PATH],
                                       'expect':'PASS'},
                                      {'desc':'kmyth-unseal, no auth string specified for auth string only policy',
                                       'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                               '-i', SEALED_KEY_PATH,
                                               '-s'],
                                       'expect':'FAIL'},
                                      {'desc':'kmyth-unseal, incorrect auth string for auth string only policy',
                                       'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                               '-i', SEALED_KEY_PATH,
                                               '-a', WRONG_AUTH_STRING,
                                               '-s'],
                                       'expect':'FAIL'},
                                      {'desc':'kmyth-getkey using correct criteria for object with auth string only policy',
                                       'args':[KMYTH_BIN_PATH / 'kmyth-getkey',
                                               '-i', SEALED_KEY_PATH,
                                               '-l', CLIENT_CERT_PATH,
                                               '-s', KEY_SERVER_CERT_PATH,
                                               '-c', KEY_SERVER_ADDRESS,
                                               '-o', OUTPUT_KEYFILE_PATH,
                                               '-a', AUTH_STRING],
                                       'expect':'PASS'},
                                      {'desc':'kmyth-getkey using auth string only policy - received key verification',
                                              'args':['diff',
                                                      OUTPUT_KEYFILE_PATH, TEST_KEY_PATH],
                                              'expect':'PASS'}]}

"""
Test Kmyth Applications with a Combination Authorization String and PCR Criteria Policy
  - non-empty authorization string
  - PCR criteria
"""
AUTHSTRING_PCR_POLICY_TEST = {'title':'Combined Authorization String and PCR Criteria Authorization Policy Test',
                              'seq':[{'desc':'kmyth-seal, auth string and PCR policy',
                                      'args':[KMYTH_BIN_PATH / 'kmyth-seal',
                                              '-i', UNSEALED_KEY_PATH,
                                              '-o', SEALED_KEY_PATH,
                                              '-a', AUTH_STRING,
                                              '-p', PCR_SELECTION,
                                              '-f'],
                                      'expect':'PASS'},
                                     {'desc':'kmyth-unseal, auth string and PCR policy',
                                      'args':[KMYTH_BIN_PATH / 'kmyth-unseal',
                                              '-i', SEALED_KEY_PATH,
                                              '-o', UNSEAL_RESULT_PATH,
                                              '-a', AUTH_STRING,
                                              '-s'],
                                      'expect':'PASS'},

                                     {'desc':'kmyth-unseal, auth string and PCR policy - result verification',
                                      'args':['diff',
                                              UNSEAL_RESULT_PATH, UNSEALED_KEY_PATH],
                                       'expect':'PASS'},
                                     {'desc':'kmyth-getkey, auth string and PCR policy',
                                      'args':[KMYTH_BIN_PATH / 'kmyth-getkey',
                                              '-i', SEALED_KEY_PATH,
                                              '-l', CLIENT_CERT_PATH,
                                              '-s', KEY_SERVER_CERT_PATH,
                                              '-c', KEY_SERVER_ADDRESS,
                                              '-o', OUTPUT_KEYFILE_PATH,
                                              '-a', AUTH_STRING],
                                      'expect':'PASS'},
                                     {'desc':'kmyth-getkey, auth string and PCR policy - received key verification',
                                             'args':['diff',
                                                     OUTPUT_KEYFILE_PATH, TEST_KEY_PATH],
                                             'expect':'PASS'}]}


"""
List of 'test sets' to run
"""
INTEGRATION_TEST_LIST = [DEFAULT_POLICY_TEST,
                         PCR_ONLY_POLICY_TEST,
                         AUTHSTRING_ONLY_POLICY_TEST,
                         AUTHSTRING_PCR_POLICY_TEST]


#-----------------------------------------------------------------------------
# Integration Test Setup
#-----------------------------------------------------------------------------
def integration_test_init(verbose_flag):
    if verbose_flag:
        print('Kmyth Integration Tests: initialization')

    # Generate test keys / certificates to be used for testing
    # < call test key setup script here >
 
    # Check process list for TCTI type parameter passed to resource manager
    # (tpm2-abrmd) call. The TCTI type should be 'mssim' if the simulator is
    # being used. The tpm_simulator flag value is used to store the result.
    tpm_simulator_flag = False
    plist = subprocess.check_output(['ps', '-aux'])
    pattern = re.compile(r'tpm2-abrmd\s+[^\n]*\-t\s+(\w+)')
    search_iterator = pattern.finditer(plist.decode())
    num_matches = 0
    for match in search_iterator:
        num_matches += 1
        if match.groups()[0] == 'mssim':
            tpm_simulator_flag = True
    # Should be single resource manager process, but check to be sure
    if (num_matches != 1):
        if verbose_flag:
            print('  {} tpm2-abrmd instances found ... exiting'.format(num_matches))
        exit()

    # Do not want to mess with TPM settings if TPM is a device
    # Only setup and run integration tests if TPM simulator is being used
    if not tpm_simulator_flag:
        if verbose_flag:
            print('  integration tests require use of TPM simulator ... exiting')
        exit()
    else:
        # Set max-tries on dictionary lockout protection to sufficient level for testing
        subprocess.Popen(['tpm2_dictionarylockout', '-s', '-n 32', '-l 0', '-t 0'])
        if verbose_flag:
            print('  temporarily disabled dictionary lockout protection ...')

        # Start Sample Key Server
        subprocess.Popen([KEY_SERVER_SCRIPT_PATH, 'start'], stdout=subprocess.DEVNULL,
                                                            stderr=subprocess.DEVNULL)
        if verbose_flag:
            print('  started sample test server ...')

#-----------------------------------------------------------------------------
# Integration Test Cleanup
#-----------------------------------------------------------------------------
def integration_test_cleanup(verbose_flag):
    if verbose_flag:
        print('Kmyth Integration Tests: clean-up')
    
    # Set max-tries on dictionary lockout protection to sufficient level for testing
    subprocess.Popen(['tpm2_dictionarylockout', '-s', '-n 3', '-l 1000', '-t 1000'])
    if verbose_flag:
        print('  restored dictionary lockout protection defaults ...')

    # Stop Sample Key Server
    subprocess.Popen([KEY_SERVER_SCRIPT_PATH, 'stop'])
    if verbose_flag:
        print('  stopped sample test server ...')

    # Get rid of any files produced during testing
    subprocess.Popen(['rm', '-f', OUTPUT_KEYFILE_PATH])
    if verbose_flag:
        print('  removed retrieved test bytes file (if exists) ...')
    subprocess.Popen(['rm', '-f', SEALED_KEY_PATH])
    if verbose_flag:
        print('  removed test sealed data file (if exists) ...')


#-----------------------------------------------------------------------------
# Integration Subtest - Invoke User Specified Test Sequence
#-----------------------------------------------------------------------------
def integration_subtest(subtest, log, verbose_flag):
    if verbose_flag:
        print(subtest['title'])
    for step in subtest['seq']:
        test = subprocess.Popen(step['args'],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        test.communicate()

        result = 'FAIL'
        if (step['expect'] == 'PASS') and (test.returncode == 0):
            result = 'PASS'
            log['PASS'] += 1
        if (step['expect'] == 'FAIL') and (test.returncode != 0):
            result = 'PASS'
            log['PASS'] += 1
        if (result == 'FAIL'):
            log['FAIL'] += 1
            log['failed tests'].append(step['desc'])
        
        if verbose_flag:
            print('  {}: '.format(step['desc']), end='')
            print('{} (rc = {})'.format(result, test.returncode))

    return(result)


#-----------------------------------------------------------------------------
# Main Testrunner Script
#----------------------------------------------------------------------------

# Check for optional 'verbose mode' option
script_cmd_parser = argparse.ArgumentParser('Kmyth Integration Test Script')
script_cmd_parser.add_argument('-v', '--verbose', action='store_true',
                                                  help='verbose output mode')
script_opts = script_cmd_parser.parse_args()
verbose_mode = script_opts.verbose

# Note start time
start_time = time.monotonic()

# Initialize test environment
integration_test_init(verbose_mode)

# Initialize test statistics
test_stats = {'PASS':0, 'FAIL':0, 'failed tests':[]}

# Loop through integration tests
for t in INTEGRATION_TEST_LIST:
    integration_subtest(t, test_stats, verbose_mode)

# Restore integration test environment to pre-test state
#integration_test_cleanup(verbose_mode)

# Note stop time and calculate elapsed time
end_time = time.monotonic()
elapsed_time = end_time - start_time

# Report test summary
print("Integration Testing Completed")
num_tests = test_stats['PASS'] + test_stats['FAIL']
print('  test count: ', end='')
print('{} total '.format (test_stats['PASS'] + test_stats['FAIL']), end='')
print('({} passed, '.format(test_stats['PASS']), end='')
print('{} failed)'.format(test_stats['FAIL']))
print('  test duration: {:>9.2f} seconds'.format(elapsed_time))
if len(test_stats['failed tests']) > 0:
    print('  failed tests:')
    for description in test_stats['failed tests']:
        print('    {}'.format(description))

