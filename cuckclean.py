#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Command line utility to either get or delete a Cuckoo SandBox analysis from a MongoDB instance
For the delete operations to work fast enough, a prerequisite is to create indexes on the fields described in the README
'''
import sys
import logging
import shutil
import click
import pymongo
import gridfs
from bson.objectid import ObjectId

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='cuckclean.log', filemode='a')


def connect():
    client = pymongo.MongoClient('<IP goes here>', 27017)
    db = client['cuckoo']
    return db


def get_analysis(db, task_id):
    '''
    Retrieve analysis document from Mongo by task ID
    '''
    doc = db.analysis.find_one({"info.id": task_id})
    return doc


def get_chunks(db, id):
    '''
    Get chunk id-s of a file
    '''
    chunk_ids = set()
    chunks = db.fs.chunks.find({"files_id": id})
    for chunk in chunks:
        chunk_ids.add(chunk['_id'])

    return chunk_ids


def get_calls(db, procs):
    '''
    Get all calls of task
    '''
    call_ids = set()
    for proc in procs:
        for call in proc['calls']:
            pid = db.calls.find_one({"_id": call})
            if pid is not None:
                call_ids.add(pid['_id'])

    return call_ids


def get_files(target, network, shots, dropped, extracted):
    '''
    Get ID-s for target file, screenshots and extracted files
    '''
    fs_ids = dict()

    if target['file_id'] is not None:
        fs_ids['target'] = target['file_id']

    if 'pcap_id' in network:
        fs_ids['pcap_id'] = network['pcap_id']

    if 'sorted_pcap_id' in network:
        fs_ids['sorted_pcap_id'] = network['sorted_pcap_id']

    if 'mitmproxy_id' in network:
        fs_ids['mitmproxy_id'] = network['mitmproxy_id']

    fs_ids['shots'] = set()
    for shot in shots:
        if isinstance(shot, dict):
            if "small" in shot:
                fs_ids['shots'].add(shot['small'])

            if "original" in shot:
                fs_ids['shots'].add(shot["original"])
            continue

    fs_ids['dropped'] = set()
    for drop in dropped:
        fs_ids['dropped'].add(drop['object_id'])

    fs_ids['extracted'] = set()
    for ext in extracted:
        for id in ext['extracted']:
            fs_ids['extracted'].add(id['extracted_id'])

    return fs_ids


@click.command()
@click.option('--task-id', default=1,  help='ID of task to retrieve from Mongo')
def get(task_id):
    '''
    Get a Cuckoo analysis from Mongo and display path
    '''

    chunks = list()
    calls = list()
    files = dict()
    db = connect()

    # Get the report from the analysis collection
    analysis = get_analysis(db, task_id)

    if analysis is None:
        click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
        sys.exit(1)

    click.echo('Analysis storage path: {}'.format(analysis['info']['analysis_path']))

    files = get_files(analysis['target'], #['file_id']
                      analysis['network'], #['sorted_pcap_id'], ['mitmproxy_id'], ['pcap_id']
                      analysis['shots'],
                      analysis['dropped'],
                      analysis['procmemory'])

    if files['target'] is not None:
        click.echo('Target file id: {}'.format(files['target']))

    # Find all chunks related to the files
    for key,values in files.items():
        click.echo('These are file ids for {0}:\n'.format(key))
        click.echo(files[key])
        click.echo('Corresponding chunks are:\n')
        try:
            for value in values:
                chunks += get_chunks(db, value)
        except TypeError:
            chunks += get_chunks(db, values)
        click.echo(chunks)
        chunks = []
        click.echo('-----------------------------------------------')

    # For every process, find id-s of all calls stored in Mongo
    if 'processes' in analysis['behavior']:
        calls = get_calls(db, analysis['behavior']['processes'])

    click.echo('-----------------------------------------------')
    click.echo('These are call_ids:\n {}'.format(calls))


@click.command()
@click.option('--task-id', default=1, help='ID of task to delete')
def delete(task_id):
    '''
    Delete the analysis and all related calls for the given Task ID
    '''

    db = connect()
    fs = gridfs.GridFS(db)

    analysis = get_analysis(db, task_id)
    if analysis is None:
        click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
        sys.exit(1)

    click.echo('Task {task_id} has Mongo id: {id}'
               .format(task_id=task_id, id=analysis['_id']))
    click.echo('Storage path for {task_id}: {path}'
               .format(task_id=task_id,
               path=analysis['info']['analysis_path']))
    
    # For every process, find id-s of all calls stored in Mongo and delete them
    if 'processes' in analysis['behavior']:
        calls = get_calls(db, analysis['behavior']['processes'])

    del_calls = dict()
    del_calls['count'] = 0
    del_calls['results'] = dict()
    for call in calls:
        click.echo('Deleting call ID: {0}'.format(call))
        del_call_result = db.calls.delete_one({"_id": call})
        del_calls['count'] += del_call_result.deleted_count
        del_calls['results'][call] = del_call_result.raw_result

    click.echo('Deleted {cnt} calls out of {total} calls for {task_id}'
               .format(cnt=del_calls['count'],
               total=len(calls), task_id=task_id))
    logging.debug(del_calls['results'])

    files = get_files(analysis['target'], #['file_id']
                      analysis['network'], #['sorted_pcap_id'], ['mitmproxy_id'], ['pcap_id']
                      analysis['shots'],
                      analysis['dropped'],
                      analysis['procmemory'])

    # Delete sample file from GridFS
    if files['target'] is not None:
        if db.analysis.find({"target.file_id": files["target"]}).count() == 1:
            click.echo('Deleting target file: {0}'.format(files['target']))
            fs.delete(files["target"])
    logging.info('Deleted sample file with ID: {file_id}'
                 .format(file_id=files["target"]))

    # Delete screenshots.
    shot_del_count = 0
    for shot in files['shots']:
        if db.analysis.find({"shots.original": shot}).count() == 1:
                    click.echo('Deleting shot file: {0}'.format(shot))
                    shot_del_count += 1
                    fs.delete(shot)
    click.echo('Total count of shots was {}'.format(len(files['shots'])))
    click.echo('I deleted {0} shots'.format(shot_del_count))

    # Delete network pcap.
    if files['pcap_id'] is not None:
        if db.analysis.find({"network.pcap_id": files["pcap_id"]}).count() == 1:
            click.echo('Deleting PCAP file: {0}'.format(files['pcap_id']))
            fs.delete(files["pcap_id"])

    # Delete sorted pcap
    #if files['sorted_pcap_id'] is not None:
    if 'sorted_pcap_id' in files:
        if db.analysis.find({"network.sorted_pcap_id": files["sorted_pcap_id"]}).count() == 1:
            click.echo('Deleting SORTED PCAP file: {0}'.format(files['sorted_pcap_id']))
            fs.delete(files["sorted_pcap_id"])

    # Delete mitmproxy dump.
    #if files['mitmproxy_id'] is not None:
    if 'mitmproxy_id' in files:
        if db.analysis.find({"network.mitmproxy_id": files["mitmproxy_id"]}).count() == 1:
            click.echo('Deleting MITMPROXY file: {0}'.format(files['mitmproxy_id']))
            fs.delete(files["mitmproxy_id"])
    
    # Delete dropped.
    drop_del_count = 0
    for drop in files["dropped"]:
        if db.analysis.find({"dropped.object_id": drop}).count() == 1:
            click.echo('Deleting droppped file: {0}'.format(drop))
            drop_del_count += 1
            fs.delete(drop)
    click.echo('Total count of droppped was {}'.format(len(files['dropped'])))
    click.echo('I deleted {0} dropped files'.format(drop_del_count))

    # Delete analysis document
    click.echo('Will delete analysis document for TASK ID: {0} and ObjectID: {1}'
                .format(task_id, analysis['_id']))
    del_analysis = db.analysis.delete_one({"_id": analysis['_id']})
    logging.info('Deleted analysis {task_id}, result was: {ack}'
                   .format(task_id=task_id, ack=del_analysis.acknowledged))
    click.echo('Deleted analysis {task_id}, got response: {ack}'
               .format(task_id=task_id, ack=del_analysis.acknowledged))
    logging.debug('Deleted analysis, got raw result: {}'.format(del_analysis.raw_result))
    logging.debug('Deleted analysis, got count: {}'.format(del_analysis.deleted_count))

    click.echo('Analysis and related data removed from Mongo, now removing storage folder at: {0}'
               .format(analysis['info']['analysis_path']))
    shutil.rmtree(analysis['info']['analysis_path'])

@click.group()
def entry_point():
    pass

entry_point.add_command(get)
entry_point.add_command(delete)

if __name__ == '__main__':
    entry_point()