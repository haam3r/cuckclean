# cuckclean

Command line utility to either get or delete a Cuckoo SandBox analysis from a MongoDB instance.

Additionally provides a prune command that is used to delete old analysis results in bulk, by specifying how many to keep.
Defaults to keeping the newest 100 000 analysis documents.

The clean command looks for gridfs files that are not referenced in any anaylsis result and deletes them.

For the delete operations to work fast enough, a prerequisite is to create indexes on several fields

Example Mongo shell commands for this:

```bash
db.analysis.createIndex({"info.id": 1})
db.analysis.createIndex({"dropped.object_id": 1})
db.analysis.createIndex({"target.file_id": 1})
db.analysis.createIndex({"network.pcap_id": 1})
db.analysis.createIndex({"network.sorted_pcap_id": 1})
db.analysis.createIndex({"network.mitmproxy_id": 1})
db.analysis.createIndex({"shots.original": 1})
db.fs.createIndex({"chunks.files_id:": 1})
db.fs.createIndex({"files.sha256:": 1})
```

## Install

Installation is done via pip, as follows:

```bash
pip install git+https://github.com/haam3r/cuckclean.git
```

## Usage

Use `cuckclean --help` to get info on available commands.
All commands need a host parameter, provided via -h or --host. e.g. `cuckclean prune -h mongo.ip.addr --keep 100000`

### Release space from MongoDB

After DB entries were removed you need to shrink the size of the collections to release space from the database to the operating system, read more at https://docs.mongodb.com/manual/reference/command/compact. Original Cuckoo database has the following collections:  *analysis, fs.chunks, fs.files*

Check how much space can be released from each collection:

```
db.<collection name>.stats().wiredTiger['block-manager']['file bytes available for reuse']
```
WiredTiger is a default storage engine in MongoDB 3.2 and higher.

To release available space:

```
db.runCommand({compact: <collection name> })
```
Depending on how much space can be released, the command execution can take from minutes to hours.

Pull requests and issues welcome
