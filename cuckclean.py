#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Command line utility to either get or delete a Cuckoo SandBox analysis from a MongoDB instance
README describes neccessary index creation tasks.
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


cli = click.Group()


def connect():
    '''
    Return a Mongo DB connection object
    '''
    client = pymongo.MongoClient('<IP goes here>', 27017)
    db = client['cuckoo']
    return db


def get_analysis(db, task_id=None, object_id=None):
    '''
    Retrieve analysis document from Mongo by task ID
    '''
    if task_id is not None:
        click.echo('Got Task ID')
        doc = db.analysis.find_one({"info.id": task_id})
    elif object_id is not None:
        click.echo('Got ObjectId')
        doc = db.analysis.find_one({"_id": object_id})
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


def get_files(target, network, shots, dropped, extracted=None):
    '''
    Get ID-s for target file, screenshots and extracted files
    '''
    fs_ids = dict()
    
    if 'category' in target:
        if target['category'] != 'url':
            if 'file_id' in target and target['file_id'] is not None:
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
        if 'object_id' in drop:
            fs_ids['dropped'].add(drop['object_id'])

    fs_ids['extracted'] = set()
    if extracted is not None:
        for ext in extracted:
            for id in ext['extracted']:
                fs_ids['extracted'].add(id['extracted_id'])

    return fs_ids


@cli.command()
@click.option('--task-id', '-tid', default=None, type=int,  help='ID of task to retrieve from Mongo')
def get(task_id=None, object_id=None):
    '''
    Get Cuckoo analysis details
    '''

    chunks = list()
    calls = list()
    files = dict()
    db = connect()

    # Get the report from the analysis collection
    if task_id is not None:
        analysis = get_analysis(db, task_id=task_id)
        if analysis is None:
            click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
            sys.exit(1)
    elif object_id is not None:
        analysis = get_analysis(db, object_id=object_id)
        if analysis is None:
            click.echo('Analysis with object ID {} not found, terminating...'.format(object_id))
            sys.exit(1)
    else:
        click.echo('No task-id or object-id provided, terminating...')
        sys.exit(1)


    click.echo('Analysis storage path: {}'.format(analysis['info']['analysis_path']))

    files = get_files(analysis.get('target', None), #['file_id']
                      analysis.get('network', None), #['sorted_pcap_id'], ['mitmproxy_id'], ['pcap_id']
                      analysis.get('shots', None),
                      analysis.get('dropped', None),
                      analysis.get('procmemory', None))

    if 'target' in files:
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
    if 'behavior' in analysis: 
        if 'processes' in analysis['behavior']:
            calls = get_calls(db, analysis['behavior']['processes'])

    click.echo('-----------------------------------------------')
    click.echo('These are call_ids:\n {}'.format(calls))


@cli.command()
@click.option('--task-id', default=1, help='ID of task to delete')
def delete(task_id=None, object_id=None):
    '''
    Delete a Cuckoo analysis
    '''

    db = connect()
    fs = gridfs.GridFS(db)

    # Get the report from the analysis collection
    if task_id is not None:
        analysis = get_analysis(db, task_id=task_id)
        if analysis is None:
            click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
            sys.exit(1)
    elif object_id is not None:
        analysis = get_analysis(db, object_id=object_id)
        if analysis is None:
            click.echo('Analysis with object ID {} not found, terminating...'.format(object_id))
            sys.exit(1)
    else:
        click.echo('No task-id or object-id provided, terminating...')
        sys.exit(1)

    click.echo('Task {task_id} has Mongo id: {id}'
               .format(task_id=task_id, id=analysis['_id']))
    click.echo('Storage path for {task_id}: {path}'
               .format(task_id=task_id,
               path=analysis['info']['analysis_path']))
    
    # For every process, find id-s of all calls stored in Mongo and delete them
    if 'behavior' in analysis:
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

    # Compile a list of all file id-s using the get_files function and delete all files that are unique
    files = get_files(analysis.get('target', None), #['file_id']
                      analysis.get('network', None), #['sorted_pcap_id'], ['mitmproxy_id'], ['pcap_id']
                      analysis.get('shots', None),
                      analysis.get('dropped', None),
                      analysis.get('procmemory', None))

    # Delete sample file from GridFS
    if 'target' in files:
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
                    logging.debug('Deleting shot file: {0}'.format(shot))
                    shot_del_count += 1
                    fs.delete(shot)
    click.echo('Total count of shots was {}'.format(len(files['shots'])))
    click.echo('I deleted {0} shots'.format(shot_del_count))

    # Delete network pcap.
    if 'pcap_id' in files:
        if db.analysis.find({"network.pcap_id": files["pcap_id"]}).count() == 1:
            click.echo('Deleting PCAP file: {0}'.format(files['pcap_id']))
            fs.delete(files["pcap_id"])

    # Delete sorted pcap
    if 'sorted_pcap_id' in files:
        if db.analysis.find({"network.sorted_pcap_id": files["sorted_pcap_id"]}).count() == 1:
            click.echo('Deleting SORTED PCAP file: {0}'.format(files['sorted_pcap_id']))
            fs.delete(files["sorted_pcap_id"])

    # Delete mitmproxy dump.
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
    click.echo('{0} dropped files were deleted'.format(drop_del_count))

    # Delete analysis document
    del_analysis = db.analysis.delete_one({"_id": analysis['_id']})
    click.echo('Deleted analysis {task_id}, got response: {ack}'
               .format(task_id=task_id, ack=del_analysis.acknowledged))
    logging.debug('Deleted analysis, got raw result: {}'.format(del_analysis.raw_result))

    # Delete storage folder from disk
    click.echo('Analysis and related data removed from Mongo, now removing storage folder at: {0}'
               .format(analysis['info']['analysis_path']))
    shutil.rmtree(analysis['info']['analysis_path'])

@cli.command()
@click.option('--keep', default=100000, help='How many analyses to keep')
@click.option('--batch_size', default=100, help='Batch size for Mongo query')
@click.pass_context
def prune(ctx, keep, batch_size):
    '''
    Prune oldest analysis results.
    By default keeps 100 000 latest analysis.
    Amount of analyses to keep can be modified with the keep option.
    '''

    db = connect()
    # Substract number of results to keep from total analysis collection count.
    # This number will be used to limit how many results sorted by oldest to newest should be returned
    total = db.analysis.count()
    if keep >= total:
        click.echo('Total docs is: {0} and you gave {1} as keep...does not compute'.format(total, keep))
        sys.exit(1)

    nr = total - keep
    click.echo('Will delete {0} documents'.format(nr))
    # Mongo ObjectId encodes document creation timestamp, so we can sort with that. It's also indexed by default.
    sorted = db.analysis.find({}).sort("_id", 1).limit(nr).batch_size(batch_size)
    
    for doc in sorted:
        click.echo('Pruning task ID: {0}, that has ObjectId: {1}'.format(doc['info']['id'], doc['_id']))
        # Cant simply invoke the delete function, because of click decorators
        ctx.invoke(delete, task_id=None, object_id=doc["_id"])


@click.group()
def entry_point():
    pass

entry_point.add_command(get)
entry_point.add_command(delete)
entry_point.add_command(prune)


if __name__ == '__main__':
    entry_point()

