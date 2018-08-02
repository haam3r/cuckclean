# cuckclean

Command line utility to either get or delete a Cuckoo SandBox analysis from a MongoDB instance.

Additionally provides a prune command that is used to delete old analysis results in bulk, by specifying how many to keep.
Defaults to keeping the newest 100 000 analysis documents.

For the delete operations to work fast enough, a prerequisite is to create indexes on several fields

Example commands for this:

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

Pull requests and issues welcome
