import logging
import argparse
import sys
from ctypes import *

from src.utils import get_pool_genesis_txn_path, PROTOCOL_VERSION, run_coroutine, ensure_previous_request_applied

import json

from indy import pool, wallet, did, ledger, anoncreds, blob_storage

from indy.error import ErrorCode, IndyError

import time

from os.path import dirname

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description= 'Run python app for (Emon/CUET) scenario')
parser.add_argument('-t', '--storage_type', help='load custom wallet storage plug-in')
parser.add_argument('-l', '--library', help='dynamic library to load for plug-in')
parser.add_argument('-e', '--entrypoint', help='entry point for dynamic linrary')
parser.add_argument('-c','--config', help='entry point for dynamic library')
parser.add_argument('-s', '--creds', help='entry point for dynamic library')

args = parser.parse_args()

# checking for custom wallet storage
if args.storage_type:
    if not (args.library and args.entrypoint):
        parser.print_help()
        sys.exit(0)
    stg_lib =CDLL(args.library)
    result = stg_lib[args.entrypoint]()
    if result != 0:
        print("Error unable to load wallet storage", result)
        parser.print_help()
        sys.exit(0)

    # for postgres storage, also call the storage init (non-standard)
    if args.storage_type == "postgres_storage":
        try:
            print("Calling init_storagetype() for postgres:", args.config, args.creds)
            init_storagetype = stg_lib["init_storagetype"]
            c_config = c_char_p(args.config.encode('utf-8'))
            c_credentials = c_char_p(args.creds.encode('utf-8'))
            result = init_storagetype(c_config, c_credentials)
            print(" ... returns ", result)
        except RuntimeError as e:
            print("Error initializing storage, ignoring ...", e)

    print("Success, loaded wallet storage", args.storage_type)


async def run():
    logger.info("App -> started")

    pool_ = {
        'name': 'pool1'
    }
    logger.info("Open Pool Ledger: {}".format(pool_['name']))
    pool_['genesis_txn_path'] = get_pool_genesis_txn_path(pool_['name'])
    pool_['config'] = json.dumps({"genesis_txn": str(pool_['genesis_txn_path'])})

    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndexError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass

    pool_['handle'] = await  pool.open_pool_ledger(pool_['name'], None)

    logger.info("==============================")
    logger.info("=== Getting Trust Anchor credentials for CUET, BJIT, City and Government  ==")
    logger.info("------------------------------")

    steward = {
        'name': "Bd Steward",
        'wallet_config': json.dumps({'id': 'bd_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    await create_wallet(steward)

    logger.info("\"Bd Steward\" -> Create and store in Wallet DID from seed")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    logger.info("------------------------------")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, government)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - CUET getting Verinym  ==")
    logger.info("------------------------------")

    cuet = {
        'name': 'Cuet',
        'wallet_config': json.dumps({'id': 'cuet_wallet'}),
        'wallet_credentials': json.dumps({'key': 'cuet_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, cuet)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - BJIT getting Verinym  ==")
    logger.info("------------------------------")

    bjit = {
        'name': 'Bjit',
        'wallet_config': json.dumps({'id': 'bjit_wallet'}),
        'wallet_credentials': json.dumps({'key': 'bjit_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, bjit)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - City getting Verinym  ==")
    logger.info("------------------------------")

    city = {
        'name': 'City',
        'wallet_config': json.dumps({'id': 'city_wallet'}),
        'wallet_credentials': json.dumps({'key': 'city_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }

    await getting_verinym(steward, city)

    logger.info("==============================")
    logger.info("=== Credential Schemas Setup ==")
    logger.info("------------------------------")

    logger.info("\"Government\" -> Create \"Job-Certificate\" Schema")
    job_certificate = {
        'name': 'Job-Certificate',
        'version': '0.2',
        'attributes': ['first_name', 'last_name', 'salary', 'employee_status', 'experience']
    }
    (government['job_certificate_schema_id'], government['job_certificate_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], job_certificate['name'], job_certificate['version'],
                                             json.dumps(job_certificate['attributes']))
    job_certificate_schema_id = government['job_certificate_schema_id']

    logger.info("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['job_certificate_schema'])

    logger.info("\"Government\" -> Create \"Transcript\" Schema")
    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    }
    (government['transcript_schema_id'], government['transcript_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    transcript_schema_id = government['transcript_schema_id']

    logger.info("\"Government\" -> Send \"Transcript\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['transcript_schema'])

    time.sleep(1)  # sleep 1 second before getting schema # sleep 1 second before getting schema

    logger.info("==============================")
    logger.info("=== CUET Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"CUET\" -> Get \"Transcript\" Schema from Ledger")
    (cuet['transcript_schema_id'], cuet['transcript_schema']) = \
        await get_schema(cuet['pool'], cuet['did'], transcript_schema_id)

    logger.info("\"CUET\" -> Create and store in Wallet \"CUET Transcript\" Credential Definition")
    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (cuet['transcript_cred_def_id'], cuet['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(cuet['wallet'], cuet['did'],
                                                               cuet['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))

    logger.info("\"CUET\" -> Send  \"CUET Transcript\" Credential Definition to Ledger")
    await send_cred_def(cuet['pool'], cuet['wallet'], cuet['did'], cuet['transcript_cred_def'])

    logger.info("==============================")
    logger.info("=== BJIT Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"BJIT\" -> Get from Ledger \"Job-Certificate\" Schema")
    (bjit['job_certificate_schema_id'], bjit['job_certificate_schema']) = \
        await get_schema(bjit['pool'], bjit['did'], job_certificate_schema_id)

    logger.info("\"BJIT\" -> Create and store in Wallet \"BJIT Job-Certificate\" Credential Definition")
    job_certificate_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (bjit['job_certificate_cred_def_id'], bjit['job_certificate_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(bjit['wallet'], bjit['did'],
                                                               bjit['job_certificate_schema'],
                                                               job_certificate_cred_def['tag'],
                                                               job_certificate_cred_def['type'],
                                                               json.dumps(job_certificate_cred_def['config']))

    logger.info("\"BJIT\" -> Send \"BJIT Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(bjit['pool'], bjit['wallet'], bjit['did'], bjit['job_certificate_cred_def'])

    logger.info("\"BJIT\" -> Creates Revocation Registry")
    bjit['tails_writer_config'] = json.dumps({'base_dir': "/tmp/indy_bjit_tails", 'uri_pattern': ''})
    tails_writer = await blob_storage.open_writer('default', bjit['tails_writer_config'])
    (bjit['revoc_reg_id'], bjit['revoc_reg_def'], bjit['revoc_reg_entry']) = \
        await anoncreds.issuer_create_and_store_revoc_reg(bjit['wallet'], bjit['did'], 'CL_ACCUM', 'TAG1',
                                                          bjit['job_certificate_cred_def_id'],
                                                          json.dumps({'max_cred_num': 5,
                                                                      'issuance_type': 'ISSUANCE_ON_DEMAND'}),
                                                          tails_writer)

    logger.info("\"BJIT\" -> Post Revocation Registry Definition to Ledger")
    bjit['revoc_reg_def_request'] = await ledger.build_revoc_reg_def_request(bjit['did'], bjit['revoc_reg_def'])
    await ledger.sign_and_submit_request(bjit['pool'], bjit['wallet'], bjit['did'], bjit['revoc_reg_def_request'])

    logger.info("\"BJIT\" -> Post Revocation Registry Entry to Ledger")
    bjit['revoc_reg_entry_request'] = \
        await ledger.build_revoc_reg_entry_request(bjit['did'], bjit['revoc_reg_id'], 'CL_ACCUM',
                                                   bjit['revoc_reg_entry'])
    await ledger.sign_and_submit_request(bjit['pool'], bjit['wallet'], bjit['did'], bjit['revoc_reg_entry_request'])


    logger.info("==============================")
    logger.info("=== Getting Transcript with CUET ==")
    logger.info("==============================")
    logger.info("== Emon setup ==")
    logger.info("------------------------------")

    emon = {
        'name': 'Emon',
        'wallet_config': json.dumps({'id': 'emon_wallet'}),
        'wallet_credentials': json.dumps({'key': 'emon_wallet_key'}),
        'pool': pool_['handle'],
    }
    await create_wallet(emon)
    (emon['did'], emon['key']) = await did.create_and_store_my_did(emon['wallet'], "{}")


    logger.info("==============================")
    logger.info("== Getting Transcript with CUET - Getting Transcript Credential ==")
    logger.info("------------------------------")

    logger.info("\"CUET\" -> Create \"Transcript\" Credential Offer for Emon")
    cuet['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(cuet['wallet'], cuet['transcript_cred_def_id'])

    logger.info("\"CUET\" -> Send \"Transcript\" Credential Offer to Emon")
    emon['transcript_cred_offer'] = cuet['transcript_cred_offer']
    transcript_cred_offer_object = json.loads(emon['transcript_cred_offer'])

    emon['transcript_schema_id'] = transcript_cred_offer_object['schema_id']
    emon['transcript_cred_def_id'] = transcript_cred_offer_object['cred_def_id']

    logger.info("\"Emon\" -> Create and store \"Emon\" Master Secret in Wallet")
    emon['master_secret_id'] = await anoncreds.prover_create_master_secret(emon['wallet'], None)

    logger.info("\"Emon\" -> Get \"CUET Transcript\" Credential Definition from Ledger")
    (emon['cuet_transcript_cred_def_id'], emon['cuet_transcript_cred_def']) = \
        await get_cred_def(emon['pool'], emon['did'], emon['transcript_cred_def_id'])

    logger.info("\"Emon\" -> Create \"Transcript\" Credential Request for CUET")
    (emon['transcript_cred_request'], emon['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(emon['wallet'], emon['did'],
                                                     emon['transcript_cred_offer'], emon['cuet_transcript_cred_def'],
                                                     emon['master_secret_id'])

    logger.info("\"Emon\" -> Send \"Transcript\" Credential Request to CUET")
    cuet['transcript_cred_request'] = emon['transcript_cred_request']



    logger.info("\"CUET\" -> Create \"Transcript\" Credential for Emon")
    cuet['emon_transcript_cred_values'] = json.dumps({
        "first_name": {"raw": "Emon", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Sagor", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Computer Science", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2018", "encoded": "2018"},
        "average": {"raw": "4", "encoded": "4"}
    })

    cuet['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(cuet['wallet'], cuet['transcript_cred_offer'],
                                                 cuet['transcript_cred_request'],
                                                 cuet['emon_transcript_cred_values'], None, None)

    logger.info("\"CUET\" -> Send \"Transcript\" Credential to Emon")
    emon['transcript_cred'] = cuet['transcript_cred']

    logger.info("\"Emon\" -> Store \"Transcript\" Credential from CUET")
    _, emon['transcript_cred_def'] = await get_cred_def(emon['pool'], emon['did'],
                                                         emon['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(emon['wallet'], None, emon['transcript_cred_request_metadata'],
                                            emon['transcript_cred'], emon['transcript_cred_def'], None)


    logger.info("==============================")
    logger.info("== Apply for the job with BJIT - Transcript proving ==")
    logger.info("------------------------------")

    logger.info("\"BJIT\" -> Create \"Job-Application\" Proof Request")
    nonce = await anoncreds.generate_nonce()
    bjit['job_application_proof_request'] = json.dumps({
        'nonce': nonce,
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': cuet['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': cuet['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': cuet['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 3,
                'restrictions': [{'cred_def_id': cuet['transcript_cred_def_id']}]
            }
        }
    })

    logger.info("\"BJIT\" -> Send \"Job-Application\" Proof Request to Emon")
    emon['job_application_proof_request'] = bjit['job_application_proof_request']

    logger.info("\"Emon\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(emon['wallet'],
                                                                emon['job_application_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    emon['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}



    emon['schemas_for_job_application'], emon['cred_defs_for_job_application'], \
    emon['revoc_states_for_job_application'] = \
        await prover_get_entities_from_ledger(emon['pool'], emon['did'],
                                              emon['creds_for_job_application_proof'], emon['name'])

    logger.info("\"Emon\" -> Create \"Job-Application\" Proof")
    emon['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'Emon',
            'attr2_referent': 'Sagor',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    emon['job_application_proof'] = \
        await anoncreds.prover_create_proof(emon['wallet'], emon['job_application_proof_request'],
                                            emon['job_application_requested_creds'], emon['master_secret_id'],
                                            emon['schemas_for_job_application'],
                                            emon['cred_defs_for_job_application'],
                                            emon['revoc_states_for_job_application'])

    logger.info("\"Emon\" -> Send \"Job-Application\" Proof to BJIT")
    bjit['job_application_proof'] = emon['job_application_proof']

    job_application_proof_object = json.loads(bjit['job_application_proof'])

    bjit['schemas_for_job_application'], bjit['cred_defs_for_job_application'], \
    bjit['revoc_ref_defs_for_job_application'], bjit['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(bjit['pool'], bjit['did'],
                                                job_application_proof_object['identifiers'], bjit['name'])

    logger.info("\"BJIT\" -> Verify \"Job-Application\" Proof from Emon")
    assert 'Bachelor of Science, Marketing' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           job_application_proof_object['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Emon' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == job_application_proof_object['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(bjit['job_application_proof_request'], bjit['job_application_proof'],
                                                 bjit['schemas_for_job_application'],
                                                 bjit['cred_defs_for_job_application'],
                                                 bjit['revoc_ref_defs_for_job_application'],
                                                 bjit['revoc_regs_for_job_application'])

    logger.info("==============================")
    logger.info("== Apply for the job with BJIT - Getting Job-Certificate Credential ==")
    logger.info("------------------------------")

    logger.info("\"BJIT\" -> Create \"Job-Certificate\" Credential Offer for Emon")
    bjit['job_certificate_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(bjit['wallet'], bjit['job_certificate_cred_def_id'])

    logger.info("\"BJIT\" -> Send \"Job-Certificate\" Credential Offer to Emon")
    emon['job_certificate_cred_offer'] = bjit['job_certificate_cred_offer']

    job_certificate_cred_offer_object = json.loads(emon['job_certificate_cred_offer'])











    logger.info("==============================")

    logger.info(" \"Bd Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    logger.info("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(wallet_config("delete", government['wallet_config']),
                               wallet_credentials("delete", government['wallet_credentials']))

    logger.info("\"CUET\" -> Close and Delete wallet")
    await wallet.close_wallet(cuet['wallet'])
    await wallet.delete_wallet(wallet_config("delete", cuet['wallet_config']),
                               wallet_credentials("delete", cuet['wallet_credentials']))

    logger.info("\"BJIT\" -> Close and Delete wallet")
    await wallet.close_wallet(bjit['wallet'])
    await wallet.delete_wallet(wallet_config("delete", bjit['wallet_config']),
                               wallet_credentials("delete", bjit['wallet_credentials']))

    logger.info("\"City\" -> Close and Delete wallet")
    await wallet.close_wallet(city['wallet'])
    await wallet.delete_wallet(wallet_config("delete", city['wallet_config']),
                               wallet_credentials("delete", city['wallet_credentials']))


    logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    logger.info("App -> demo done")









def wallet_config(operation, wallet_config_str):
    if not args.storage_type:
        return wallet_config_str
    wallet_config_json = json.loads(wallet_config_str)
    wallet_config_json['storage_type'] = args.storage_type
    if args.config:
        wallet_config_json['storage_config'] = json.loads(args.config)
    # print(operation, json.dumps(wallet_config_json))
    return json.dumps(wallet_config_json)


def wallet_credentials(operation, wallet_credentials_str):
    if not args.storage_type:
        return wallet_credentials_str
    wallet_credentials_json = json.loads(wallet_credentials_str)
    if args.creds:
        wallet_credentials_json['storage_credentials'] = json.loads(args.creds)
    # print(operation, json.dumps(wallet_credentials_json))
    return json.dumps(wallet_credentials_json)


async def create_wallet(identity):
    logger.info("\"{}\" -> Create wallet".format(identity['name']))
    try:
        await wallet.create_wallet(wallet_config("create", identity['wallet_config']),
                                   wallet_credentials("create", identity['wallet_credentials']))
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    identity['wallet'] = await wallet.open_wallet(wallet_config("open", identity['wallet_config']),
                                                  wallet_credentials("open", identity['wallet_credentials']))


async def getting_verinym(from_, to):
    await create_wallet(to)

    (to['did'], to['key']) = await did.create_and_store_my_did(to['wallet'], "{}")

    from_['info'] = {
        'did': to['did'],
        'verkey': to['key'],
        'role': to['role'] or None
    }

    await send_nym(from_['pool'], from_['wallet'], from_['did'], from_['info']['did'],
                   from_['info']['verkey'], from_['info']['role'])


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ensure_previous_request_applied(
        pool_handle, get_schema_request, lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_schema_response(get_schema_response)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = \
        await ensure_previous_request_applied(pool_handle, get_cred_def_request,
                                              lambda response: response['result']['data'] is not None)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp_from=None,
                                          timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Create Revocations States
            logger.info("\"{}\" -> Get Revocation Registry Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            logger.info("\"{}\" -> Get Revocation Registry Delta from Ledger".format(actor))
            if not timestamp_to: timestamp_to = int(time.time())
            get_revoc_reg_delta_request = \
                await ledger.build_get_revoc_reg_delta_request(_did, item['rev_reg_id'], timestamp_from, timestamp_to)
            get_revoc_reg_delta_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_delta_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_delta_json, t) = \
                await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)

            tails_reader_config = json.dumps(
                {'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']),
                 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)

            logger.info('%s - Create Revocation State', actor)
            rev_state_json = \
                await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json,
                                                        revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)

async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Get Revocation Definitions and Revocation Registries
            logger.info("\"{}\" -> Get Revocation Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_def_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            logger.info("\"{}\" -> Get Revocation Registry from Ledger".format(actor))
            if not timestamp: timestamp = item['timestamp']
            get_revoc_reg_request = \
                await ledger.build_get_revoc_reg_request(_did, item['rev_reg_id'], timestamp)
            get_revoc_reg_response = \
                await ensure_previous_request_applied(pool_handle, get_revoc_reg_request,
                                                      lambda response: response['result']['data'] is not None)
            (rev_reg_id, rev_reg_json, timestamp2) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)