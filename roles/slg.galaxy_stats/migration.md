# Migration to S3 log files

Plan to migrate these scripts to a dedicated host. They will need to:

- Read Nginx logs from S3
- Interact with a remote Galaxy database

## current_stats.sh, daily_stats.sh

- gxadmin locally installed with remote connection
- Connect to remote DB with the given env vars

## galaxy_disk_usage.py
- Trickier as needs shell access to head node volumes
- Could still be done over SSH?

## get_queue_size.py
- Needs access to head node's job_conf.yml
- Needs shell access to sinfo - could be done over SSH?
- Needs psql connection

## monthly_stats_collector.py
- gxadmin locally installed with remote connection
