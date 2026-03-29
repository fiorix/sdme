+++
title = "Running an OCI Database with Volumes"
description = "Run PostgreSQL with automatically managed OCI volumes that persist data across container removal and re-creation."
weight = 8
+++

Some OCI images declare volumes for data directories that should
persist independently from the container. sdme detects these
declarations and automatically creates host-side directories that
are bind-mounted into the container.

This tutorial demonstrates OCI auto-volumes using PostgreSQL,
which declares `/var/lib/postgresql` as a volume.

## Import PostgreSQL

Make sure you have a base rootfs imported (see the
[different rootfs](/tutorial/different-rootfs/) tutorial). Then
import PostgreSQL as an OCI application:

```sh
sudo sdme fs import postgres docker.io/postgres --base-fs ubuntu
```

Verify that sdme detected the volume declaration:

```sh
sudo cat /var/lib/sdme/fs/postgres/oci/apps/postgres/volumes
```

You should see `/var/lib/postgresql`.

## Create and start the container

PostgreSQL requires a password to be set via the `POSTGRES_PASSWORD`
environment variable. Use `--oci-env` to pass it:

```sh
sudo sdme create mydb -r postgres --oci-env POSTGRES_PASSWORD=secret
sudo sdme start mydb
```

sdme automatically creates a host directory at
`/var/lib/sdme/volumes/mydb/var-lib-postgresql` and bind-mounts
it into the container at
`/oci/apps/postgres/root/var/lib/postgresql`.

You can verify the volume is mounted:

```sh
sudo ls -la /var/lib/sdme/volumes/mydb/
```

## Check the logs

```sh
sudo sdme logs mydb --oci
```

PostgreSQL should be running and ready to accept connections.

## Connect to the database

Since the container shares the host network, PostgreSQL is
accessible on localhost:5432. From the host:

```sh
sudo sdme exec mydb --oci -- psql -U postgres -c 'SELECT version();'
```

## Data persistence

The key benefit of OCI volumes is that data persists even when
the container is removed.

Create a test table:

```sh
sudo sdme exec mydb --oci -- psql -U postgres -c 'CREATE TABLE test (id int, name text);'
```

```sh
sudo sdme exec mydb --oci -- psql -U postgres -c "INSERT INTO test VALUES (1, 'hello');"
```

Remove the container:

```sh
sudo sdme stop mydb
sudo sdme rm mydb
```

The volume data is still on the host:

```sh
sudo ls -la /var/lib/sdme/volumes/mydb/
```

Create a new container from the same rootfs:

```sh
sudo sdme create mydb -r postgres --oci-env POSTGRES_PASSWORD=secret
sudo sdme start mydb
```

Verify the data survived:

```sh
sudo sdme exec mydb --oci -- psql -U postgres -c 'SELECT * FROM test;'
```

## Where volumes live on the host

OCI volume data is stored under `/var/lib/sdme/volumes/{container}/`.
The volume path from the OCI image is sanitized (slashes replaced
with dashes) to create the directory name:

```
/var/lib/postgresql  ->  /var/lib/sdme/volumes/mydb/var-lib-postgresql
```

## Suppressing auto-volumes

If you don't want sdme to auto-mount the declared volumes, use
`--no-oci-volumes`:

```sh
sudo sdme create mydb -r postgres --no-oci-volumes
```

You can also use `--bind` to override a specific volume path with
your own host directory. User `--bind` flags take priority over
auto-volumes for the same container path.

## Other images with volumes

Many database and stateful images declare volumes in their OCI
config:

- **mysql**: `/var/lib/mysql`
- **mariadb**: `/var/lib/mysql`
- **postgres**: `/var/lib/postgresql`
- **mongo**: `/data/db`, `/data/configdb`

Not all images declare volumes. For example, redis and nginx do not.
Use `--bind` to manage data directories for those images manually.
See the [bind mounts](/tutorial/bind-mounts-volumes/) tutorial for
details.
