# Remote access controls

When designing a backup plan, we must remember that if a malicious agent compromises your computer,
it may be able to delete your backups too. To solve this issue bupstash supports access controls on remote repositories
that can be configured on a per ssh key basis. To do this, we can utilize ssh force commands to restrict a backup client to
only run an instance of `bupstash serve` that has limited permissions.

The following assumes you have a backup server with a user called `backups` that has openssh sshd running,
and a client computer with an ssh client installed.

In an your sshd config file in your server add the line:

```
Match User backups
    ForceCommand "/bin/bupstash-put-force-command.sh"
```

Create /bin/bupstash-put-force-command.sh on your server:

```
$ echo 'exec bupstash serve --allow-put /home/backups/bupstash-backups' > bupstash-put-force-command.sh
$ sudo cp bupstash-put-force-command.sh /bin/bupstash-put-force-command.sh
$ sudo chown root:root /bin/bupstash-put-force-command.sh
$ sudo chmod +x /bin/bupstash-put-force-command.sh
```

Next add an ssh key you intend to use for backups to `$SERVER/home/backups/.ssh/authorized_keys`,
such that the user sending backups can connect to the remote server using ssh key based login.

Now when the backups user attempts to run a backup via ssh they are only able to
run the bupstash serve command with a hard coded set of permissions and
repository path.

Now the client is only authorized to create new backups, but not list or remove them:

```
export BUPSTASH_REPOSITORY="ssh://backups@$SERVER/backups"
$ bupstash put ./files
...
$ bupstash list
server has disabled query and search for this client
```

The `bupstash serve` command also supports allowing fetching data, entry removal and garbage collection. With these
options we can create a backup plan where clients can create new backups, and an administrator is able to cycle old backups
from the secure machine.
