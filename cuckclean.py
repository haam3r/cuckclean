#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import logging
import click
import pymongo
import gridfs

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='/root/cuckclean.log', filemode='a')


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


def get_files(db, target, pcap_id, sorted_pcap_id, mitmproxy_id, shots, dropped, extracted):
    '''
    Get ID-s for target file, screenshots and extracted files
    '''
    fs_ids = set()
    #fs = gridfs.GridFS(db)
    #target_file = fs.find_one({"_id": target})
    #fs_ids.add(target_file._id)
    fs_ids.add(target)

    #pcap_file = fs.find_one({"_id": pcap_id})
    #fs_ids.add(pcap_file._id)
    fs_ids.add(pcap_id)

    #sorted_pcap_file = fs.find_one({"_id": sorted_pcap_id})
    #fs_ids.add(sorted_pcap_file._id)
    fs_ids.add(sorted_pcap_id)

    #mitmproxy_file = fs.find_one({"_id": mitmproxy_id})
    #fs_ids.add(mitmproxy_file._id)
    fs_ids.add(mitmproxy_id)

    for shot in shots:
        #original = fs.find_one({"_id": shot['original']})
        #fs_ids.add(original._id)
        fs_ids.add(shot['original'])
        #small = fs.find_one({"_id": shot['small']})
        #fs_ids.add(small._id)
        fs_ids.add(shot['small'])
    
    for drop in dropped:
        #droppped_file = fs.find_one({"_id": drop["object_id"]})
        #fs_ids.add(droppped_file._id)
        fs_ids.add(drop['object_id'])

    for ext in extracted:
        for id in ext['extracted']:
            fs_ids.add(id['extracted_id'])

    return fs_ids


@click.command()
@click.option('--task_id', default=1,  help='ID of task to retrieve from Mongo')
def get(task_id):
    '''
    Get a Cuckoo analysis from Mongo and display path
    '''

    chunks = list()
    procs = dict()
    calls = list()
    files = list()
    db = connect()

    # Get the report from the analysis collection
    analysis = get_analysis(db, task_id)

    if analysis is None:
        click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
        sys.exit(1)

    click.echo('Analysis storage path: {}'.format(analysis['info']['analysis_path']))

    if 'file_id' in analysis['target']:
        click.echo('Target file id: {}'.format(analysis['target']['file_id']))
        files = get_files(db,
                            analysis['target']['file_id'],
                            analysis['network']['pcap_id'],
                            analysis['network']['sorted_pcap_id'],
                            analysis['network']['mitmproxy_id'],
                            analysis['shots'],
                            analysis['dropped'],
                            analysis['procmemory'])

    # Find all chunks related to the files
    for file in files:
        chunks += get_chunks(db, file)

    # For every process, find id-s of all calls stored in Mongo
    try:
        procs = analysis['behavior']['processes']
    except KeyError:
        logging.debug('No calls found for task ID: {}'.format(task_id))

    # procs = analysis['behavior']['processes']
    calls = get_calls(db, procs)

    click.echo('These are chunk_ids:\n {}'.format(chunks))
    click.echo('-----------------------------------------------')
    click.echo('These are fs_ids:\n {}'.format(files))
    click.echo('-----------------------------------------------')
    click.echo('These are call_ids:\n {}'.format(calls))


@click.command()
@click.option('--task_id', default=1, help='Task ID')
def delete(task_id):
    '''
    Delete the analysis and all related calls for the given Task ID
    '''

    procs = dict()
    db = connect()
    analysis = get_analysis(db, task_id)
    if analysis is None:
        click.echo('Analysis with task ID {} not found, terminating...'.format(task_id))
        sys.exit(1)

    try:
        procs = analysis['behavior']['processes']
    except KeyError:
        logging.debug('No calls found for task ID: {}'.format(task_id))

    calls = get_calls(db, procs)

    click.echo('Task {task_id} has Mongo id: {id}'
               .format(task_id=task_id, id=analysis['_id']))
    click.echo('Storage path for {task_id}: {path}'
               .format(task_id=task_id,
               path=analysis['info']['analysis_path']))
    #click.echo('Number of calls: {calls} for task {task_id}'
    #           .format(calls=len(calls), task_id=task_id))

    del_calls = dict()
    del_calls['count'] = 0
    del_calls['results'] = dict()
    for call in calls:
        click.echo('Deleting call ID: %s' % call)
        del_call_result = db.calls.delete_one({"_id": call})
        del_calls['count'] += del_call_result.deleted_count
        del_calls['results'][call] = del_call_result.raw_result

    click.echo('Deleted {cnt} calls out of {total} calls for {task_id}'
               .format(cnt=del_calls['count'],
               total=len(calls), task_id=task_id))
    logging.debug(del_calls['results'])

    del_analysis = db.analysis.delete_one({"_id": analysis['_id']})
    logging.info('Deleted analysis {task_id}, result was: {ack} and count was: {count}'
                   .format(task_id=task_id, ack=del_analysis.acknowledged,
                   count=del_analysis.deleted_count))
    click.echo('Deleted analysis {task_id}, got response: {ack}'
               .format(task_id=task_id, ack=del_analysis.acknowledged))
    #logging.debug('Deleted analysis, got raw result: {}'.format(del_analysis.raw_result))
    #logging.debug('Deleted analysis, got count: {}'.format(del_analysis.deleted_count))

@click.group()
def entry_point():
    pass

entry_point.add_command(get)
entry_point.add_command(delete)

if __name__ == '__main__':
    entry_point()