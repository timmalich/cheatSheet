# cheatSheet

## SUSE
```
﻿ ____  _   _ ____  _____ 
/ ___|| | | / ___|| ____|
\___ \| | | \___ \|  _|  
 ___) | |_| |___) | |___ 
|____/ \___/|____/|_____|
$$SUSE $$SLES
```
```bash
# setup network proxy
sudo vim /etc/sysconfig/proxy 
PROXY_ENABLED="yes"
HTTP_PROXY="http://user:pass@host:port"
HTTPS_PROXY="http://user:pass@host:port"
```
 
## SSH
```
 ____ ____  _   _ 
/ ___/ ___|| | | |
\___ \___ \| |_| |
 ___) |__) |  _  |
|____/____/|_| |_|
$$ssh
  ```
### virtual terminals with screen
```bash
# 1. enter screen 
screen 
# 2. create a new terminal
Ctrl+A+C -> new terminal
# 3. run all your epic comands ...
# 4. (optional) if required you can open antoher terminal
Ctrl+A+N -> next terminal (switching)
# 5. Detach the current terminal so another screen session can occupy it
Ctrl+A+D -> Detach
# 6. now you can open another ssh session and reload the detached screens with:
screen -r
```
### connect to server over gateway:
```bash
ssh -4 userid@userOnRemoteHost@host@gatewayHost \
-L 9044:localhost:9043 \
-L  3894:LDAP1HOST:3893 \
-L  3895:LDAP2HOST:3893 \
-L  localhost:7777:localhost:7777 \
-L  8879:localhost:8879
```
```bash
# ssh-add -L issue / no auto login
ssh-add -L
> error fetching identities: Invalid key length
# solution check that there are NO WRONG KEY FILES in .ssh. Even if you don't use it or has a crazy name 
```

### resume scp file copy
```bash
# assume `scp gemsops:/data/ZC9XAP01.0.zc9xap01.DBPART000.20200908010006.001 ~/` was startet and broke
# use rsync to resume
rsync --partial -rsh=ssh gemsops:/data/gems/postgresql/archive/pggemsprod/daily/pg_sedcbgem002pd0_PGBASEBACKUP_2021-01-19.Tuesday/ ~/backups/

```

## Java / JVM
```
   _                       __      __      __ _   __
  (_) __ ___   ____ _     / /     | \ \   / /  \/  |
  | |/ _` \ \ / / _` |   / /   _  | |\ \ / /| |\/| |
  | | (_| |\ V / (_| |  / /   | |_| | \ V / | |  | |
 _/ |\__,_| \_/ \__,_| /_/     \___/   \_/  |_|  |_|
|__/                                                
$$java $$jvm
```
### add a new certificate to keystore
```
# 1. download certificate via openssl
openssl s_client -connect host:443 > mySuperCoolNewCertifcate.cert </dev/null
# 2. add certificate to required keystore
sudo keytool -import -noprompt -trustcacerts -alias nexus -file mySuperCoolNewCertifcate.cert -keystore /opt/jdk1.8.0_45/jre/lib/security/cacerts -storepass changeit
rm mySuperCoolNewCertifcate.cert
```

##mongo
```
 _ __ ___   ___  _ __   __ _  ___  
| '_ ` _ \ / _ \| '_ \ / _` |/ _ \ 
| | | | | | (_) | | | | (_| | (_) |
|_| |_| |_|\___/|_| |_|\__, |\___/ 
                       |___/       
$$mongo
```
### example statements in mongo client
```
# switch to runtimeApi db first
use runtimeApi

# find something in collection user by id
db.user.find( { _id: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXX" } )

# find any organization
db.organization.find()

# delete element in array
# the authorization element properties are combined by and. one must not specify any element
db.user.update(
 {"_id" :"RAPI"}, {$pull : {"authorizations" :         {
	"applicationId" : "X2",
	"name" : "N2",
	"organizationScope" : "O2",
	"customScope" : "C2"
 }}})
```


## helm
```
 _          _           
| |__   ___| |_ __ ___  
| '_ \ / _ \ | '_ ` _ \ 
| | | |  __/ | | | | | |
|_| |_|\___|_|_| |_| |_|
$$helm
```
### install first release / init helm:
```
# note: with this env var you actually could skip all --tiller-namespace attributes
export TILLER_NAMESPACE=mobile

# create service account for tiller
kubectl create serviceaccount gemsadm

# Initialize tiller with the i3-helm service account
helm init --override "spec.template.spec.containers[0].args={--listen=localhost:44134},spec.template.spec.securityContext.runAsUser=1234" --tiller-image DOCKERREGISTRY_TILLER_IMAGE --tiller-namespace mobile --service-account gemsadm --upgrade

# Check version of deployed tiller, should return the equivalent version number for client and server
helm --tiller-namespace mobile version

# Give gemsadm the admin role in the default namespace, so that tiller is able to deploy helm charts in this namespace.
# Repeat this step for multiple namespaces, if required
# note that the clusterrole cluster-admin is actually pretty mighty. use w/ care or supply direct permissions
kubectl create rolebinding gemsadm-cluster-admin --clusterrole=cluster-admin --serviceaccount=mobile:gemsadm

# check if deployment as gemsadm is working:
kubectl --namespace mobile get deploy tiller-deploy -o yaml | grep gemsadm

# initially install it
helm install --tiller-namespace=mobile --set image.tag=0.0.1 -f gems-mobile-ui/values.yaml -n mobile-prod ./gems-mobile-ui/
```

## TODO 
Add helm upgrade folder to git ignore
1) install helm
1.1) cd rapi
2) helm plugin install https://github.com/app-registry/quay-helmv3-plugin
3) helm quay pull reg-dhc.app.corpintra.net/i3/postgresql-helm:stable
4) helm upgrade postgres i3_postgresql-helm_3.1.1-2020.4.27/postgresql-helm/ --install --kube-context=minikube --namespace rapi-local -f kubernetes/postgres/values.yaml
4.1) Init script
5) kubectl port-forward postgres-postgresql-helm-0 64000:64000 --address=0.0.0.0

helm upgrade postgres i3_postgresql-helm_3.1.1-2020.4.27/postgresql-helm/ --install --kube-context={{ .KUBE_CONTEXT }} --namespace {{ .NAMESPACE }} -f kubernetes/postgres/values.yaml


docker run -it -p 64000:64000 -e PGDBADMPW='rapi' -e PGDBADM='rapi' -e PGDATABASE='db' --entrypoint /bin/bash reg-dhc.app.corpintra.net/i3/postgresql:10.12-3-latest -c ./pg_start.sh


## kubernetes
```
 _          _                          _            
| | ___   _| |__   ___ _ __ _ __   ___| |_ ___  ___ 
| |/ / | | | '_ \ / _ \ '__| '_ \ / _ \ __/ _ \/ __|
|   <| |_| | |_) |  __/ |  | | | |  __/ ||  __/\__ \
|_|\_\\__,_|_.__/ \___|_|  |_| |_|\___|\__\___||___/
$$kubernetes
```
### deploy services
```bash
kubectl apply -f "alertmanager-service.yaml","grafana-service.yaml","jhipster-registry-service.yaml","keycloak-service.yaml","myapp-app-service.yaml","myapp-mongodb-service.yaml","prometheus-service.yaml","alertmanager-deployment.yaml","alertmanager-claim0-persistentvolumeclaim.yaml","grafana-deployment.yaml","myapp-grafana-data-persistentvolumeclaim.yaml","jhipster-registry-deployment.yaml","jhipster-registry-claim0-persistentvolumeclaim.yaml","keycloak-deployment.yaml","keycloak-claim0-persistentvolumeclaim.yaml","myapp-app-deployment.yaml","myapp-mongodb-deployment.yaml","prometheus-deployment.yaml","prometheus-claim0-persistentvolumeclaim.yaml","myapp-prometheus-data-persistentvolumeclaim.yaml"    
```

### exec
# note the --
k -n rapi-dev exec dev-postgresql-0 -c database -- tail -f -n 10 /srv/postgresql/volume/var/pg_logfile-4

### create a namespaces:
```
# create file
{
  "apiVersion": "v1",
  "kind": "Namespace",
    "name": "zt",
  "metadata": {
    "labels": {
      "name": "this-is-a-label"
    }
  }
}
# and run with the file
kubectl create -f namespace-tz.json 

# create cli namespace
kubectl create namespace simple

# permanently add a namespace in config:
kubectl config set-context --current --namespace=zt
```

### switch/use a context (a context describes all settings including login and creds)
```
# the last parameter is the context name. note that a context is mapped on a cluster
kubectl config use-context c12p030-admin
# or alternatively (guessing that this is just the same)
kubectx c12p030-admin
```

### pods
```
# show pods of current context:
kubectl get pods

# detailed information for a pod
kubectl describe pod PODID

# single delete pod
kubectl delete pod PODID

# connect into default pod container sh
kubectl exec -it podName sh
# connect into specific container:
kubectl exec -it runtimeapi-6f4d9598f4-vfmp9 -c init-ds sh

# show pod logs
kubectl logs -f runtimeapi-app-0
# show pod logs of init container (after -c):
kubectl logs runtimeapi-6f4d9598f4-vfmp9 -c init-ds

# watch pods
kubectl get pods -w

# get pod by label
kubectl get pod -l app=LABEL -o jsonpath="{.items[0].metadata.name}"

# grep pod by name and show it's logs
kubectl --tail=20 -nmonitoring logs -f $(kubectl -nmonitoring get pods --no-headers -o custom-columns=":metadata.name" | grep dev-simple-api-alert)

```

### networking
```
# expose to host
kubectl port-forward dev-postgresql-0 --address=0.0.0.0 64001:64000

# portfowarding from container to localhost: (first port is for your local host)
kubectl port-forward dev-postgresql-0 64001:64000

# tcpdump all http requests
tcpdump -i any -A -vv -s 0 | grep -e "Host: "

# find container port:
kubectl get pods -n logging gemslogging-kibana-7f67dbbcdd-7dqqk --template='{{(index (index .spec.containers 0).ports 0).containerPort}}{{"\n"}}'
```

### Install Script Kustomize
```bash
sudo apt install curl git
curl -L -o /tmp/latestKustomize.html https://github.com/kubernetes-sigs/kustomize/releases/latest
latestKustomize=$(grep -o '<a href=".*linux_amd64.tar.gz"' /tmp/latestKustomize.html | cut -d \" -f2)
curl -L -o /tmp/latest.tar.gz https://github.com${latestKustomize}
```

### secrets
<p style='color:red'>
<b>FIRST OF ALL! WHEN ENCODING SECRETS WITH BASE64 MAKE SURE YOU DO NOT ENCODE \n!!!!!!</b>
</p>

```bash
# encode a something: (DO NOT FORGET THE -n)
echo -n "password" | base64
# decode a something: 
echo "cGFzc3dvcmQ=" | base64 -d
```

Example secret.yaml
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
type: Opaque
data:
  mypassword: cGFzc3dvcmQ=
```

Use it in other units like this:
```yaml
apiVersion: apps/v1
kind: StatefulSet**
metadata:
  name: myotherunit
spec:
  template:
    spec:
      containers:
        - name: mycontainer
          env:
            - name: MY_PASSWORD_AS_ENV_VAR
              valueFrom:
                secretKeyRef:
                  name: my-secret
                  key: mypassword
```

Show secrets:
```bash
kubectl get secrets
kubectl describe secrets my-secret
```

### get kubernets host / cluster ip:
```bash
kubectl get svc -n default
```

### workaround for local rabbitmq dns issue:
```bash
clusterIP=$(kubectl get svc -n default -o jsonpath="{.items[0].spec.clusterIP}")
sed -i "s/cluster_formation.k8s.host = kubernetes.default.svc.cluster.local/cluster_formation.k8s.host = ${clusterIP}/g" kubernetes/rabbitmq/base/configuration.yaml
```

## Docker
```bash
$$$$$$$\                      $$\                           
$$  __$$\                     $$ |                          
$$ |  $$ | $$$$$$\   $$$$$$$\ $$ |  $$\  $$$$$$\   $$$$$$\  
$$ |  $$ |$$  __$$\ $$  _____|$$ | $$  |$$  __$$\ $$  __$$\ 
$$ |  $$ |$$ /  $$ |$$ /      $$$$$$  / $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |  $$ |$$ |      $$  _$$<  $$   ____|$$ |      
$$$$$$$  |\$$$$$$  |\$$$$$$$\ $$ | \$$\ \$$$$$$$\ $$ |      
\_______/  \______/  \_______|\__|  \__| \_______|\__|      
$$docker
```

### what is what
Dockerfile => mostly used to store parameters for docker run
docker build +> creates a new image from Dockerfile
docker run => run's a new container instance based on a image (date will therefore be "lost")
docker container restart => restarts a container. Data will still exist within this container
docker system df -v > show detailed file system usage
docker ps --size => show disk space by container

### examples
```bash
docker build -t DOCKERHUBHOST/tmalich/brm:initialized .
docker push DOCKERHUBHOST/tmalich/brm:initialized
# all others might now be able to run this without building
docker run -d -p 1521:1521 --name brm DOCKERHUBHOST/tmalich/brm:initialized

# connect to running docker
docker exec -it gems-was bash

# connect to a not runnign broken container
docker run --name gems-rest-client -it DOCKERHUBHOST/gems/gems-rest-client bash

# fork a repo (push an image to tss hub)
docker pull wnameless/oracle-xe-11g
docker tag wnameless/oracle-xe-11g DOCKERHUBHOST/tmalich/brm:init
# docker login ( if not already done)
docker push dockerhubURL/tmalich/brm:init

# publish new image:
# docker commit -m  message container REPO:TAG
  docker commit -m "static content" optimistic_chatelet DOCKERHUBHOST/gems/gems-rest-client:staticContent
  docker push DOCKERHUBHOST/gems/gems-rest-client:staticContent

# reclaim disk space
docker system prune -a
```

## Postgres
$$postgresql
### prod backup doesn't start due to leck of memory:
in host:
mount -o remount,size=4g -t tmpfs /var/lib/docker/containers/CONTAINERID/mounts/shm/

in container: 
vi /srv/postgresql/data/pggemsprod/postgresql_gems.conf
set shared_buffers = 8214MB

pg_ctl -D /srv/postgresql/data/pggemsprod/ start

and security bootstrap with local credentials as shown in 
/home/tmalich/git-repos/gems/5200_Application_Configuration/local-dev-environment/postgresql/init.sh

### logging k8s
Log connections on integration test db:
```bash
docker exec -it postgres-inttest-64000 vi /srv/postgresql/volume/data/postgres/postgresql.conf
# modify:
# log_connections = on
docker exec -it postgres-inttest-64000 /srv/postgresql/product/11.7/bin/pg_ctl -D /srv/postgresql/volume/data/postgres reload
```

Log statement on kubernetes db:
```bash
# try by sql and run an master postgres:
k exec -it dev-postgresql-0 -- bash -c ". ~/.bashrc; psql -c \"alter database db set log_min_duration_statement = '0';\""
k exec -it dev-postgresql-0 -- bash -c ". ~/.bashrc; psql -c \"alter database db set log_statement = 'all';\""

# deactivate
k exec -it dev-postgresql-0 -- bash -c ". ~/.bashrc; psql -c \"alter database db set log_statement = 'none';\""
k exec -it dev-postgresql-0 -- bash -c ". ~/.bashrc; psql -c \"alter database db set log_min_duration_statement = '-1';\""

# modify: 
# log_statement = 'all'                 # none, ddl, mod, all
# log_min_duration_statement = '0' # -1 none, 0 all
k exec -it dev-postgresql-1 -- vi /srv/postgresql/volume/data/postgres/postgresql.conf
k exec -it dev-postgresql-2 -- vi /srv/postgresql/volume/data/postgres/postgresql.conf

k exec -it dev-postgresql-0 -- /srv/postgresql/product/11.7/bin/pg_ctl -D /srv/postgresql/volume/data/postgres reload
k exec -it dev-postgresql-1 -- /srv/postgresql/product/11.7/bin/pg_ctl -D /srv/postgresql/volume/data/postgres reload
k exec -it dev-postgresql-2 -- /srv/postgresql/product/11.7/bin/pg_ctl -D /srv/postgresql/volume/data/postgres reload

```

### general
```
show databases:
\list

show roles:
\du

show schemas:
\dn

show tables all schemas:
\dt *.*

show tables of one schema
\dt gemsschema.*



# watch long runnning queries:
# NOTE IN CASE CONNECTION POOLING IS ACTIVE, THE STATE SHOULD BE active and not idle. When state=idle this table still shows the last query. This can be missleading.
watch "psql -c \"SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state FROM pg_stat_activity WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes' and state != 'idle'; \""

# tail log for queries with parameters (requries e.g. log_statement = 'all')
alias tailpglogs_for_statementswithparameters="tail -f /srv/postgresql/var/pggemsdev/log/postgresql-$(date '+%Y-%m-%d').log | grep -A1 --line-buffered 'LOG:  execute'"


# logs are here:
less /srv/postgresql/var/pggemsdev/log/

# loop over every single row and exec update:
DO $$
DECLARE rec RECORD;
BEGIN
    FOR rec IN (SELECT user_id FROM gemsschema.user2drd) LOOP
            -- raise will print console output
            --RAISE INFO '%', rec;
            UPDATE gemsschema.user2drd SET user_dirty = 0 where user_id = rec.user_id;
    END LOOP;
END;
$$ LANGUAGE PLPGSQL;

```


## DB2
```

      $$\ $$\        $$$$$$\  
      $$ |$$ |      $$  __$$\ 
 $$$$$$$ |$$$$$$$\  \__/  $$ |
$$  __$$ |$$  __$$\  $$$$$$  |
$$ /  $$ |$$ |  $$ |$$  ____/ 
$$ |  $$ |$$ |  $$ |$$ |      
\$$$$$$$ |$$$$$$$  |$$$$$$$$\ 
 \_______|\_______/ \________|
$$db2
```
### Put Online Backup into container
Backups are here: /srv/db2/home/zc9xap01/DB-BACKUPS_DAILY/cron_backup/BACKUP_INDV/zc9xap01_ZC9XAP01/
There should only be files ending with .001. Each is a complete backup, so you only need to copy one!
```bash
# Optional: tar and gzip it. Afterwards it's usually half the size
tar -zcvf /dbshare/prdbckup20200616.tar.gz /srv/db2/home/zc9xap01/DB-BACKUPS_DAILY/cron_backup/BACKUP_INDV/zc9xap01_ZC9XAP01/ZC9XAP01.0.zc9xap01.DBPART000.TIMESTAMP.*
# Also Optional but highly recommended. Copy it to opsserver first (thanks to direct network communication it will copy with ~100Mbit/s)
ssh opsserver: 
   scp gems-prod-db:/dbshare/prdbckup20200616.tar.gz /srv/tmp
# on client again (4 times faster in VPN. thanks to susshi gateway it only copies w/ ~500kb):
mkdir ~/backupZc9xap01/
scp opsserver:/srv/tmp/prdbckup20200616.tar.gz ~/backupZc9xap01/
# untar
tar -zxvf ~/backupZc9xap01/prdbckup20200616.tar.gz
# move to volume mount, so it can be read from container
mv ~/backupZc9xap01/srv ~/git-repos/gems/5100_Workspace/rait_db_scripts/
# stop gems
docker stop gems-was

#### go into container
docker exec -it gems-db2-ui bash
cd /db_scripts/srv/db2/home/zc9xap01/DB-BACKUPS_DAILY/cron_backup/BACKUP_INDV/zc9xap01_ZC9XAP01

### it's a bit more complicated here, because we want to transfer the data from xap01 int xat01
# create folder structure
db2 restore db zc9xap01 taken at TIMESTAMP_FROM_FILENAME into zc9xat01 redirect generate script /tmp/restore_zc9xap01_to_zc9xat01.sql
vi /tmp/restore_zc9xap01_to_zc9xat01.sql
---> set update command to:
UPDATE COMMAND OPTIONS USING S ON Z ON /tmp/restoring.out V ON;
---> replace every zc9xap01 with zc9xat01 DESPISE those four lines:
     RESTORE DATABASE ZC9XAP01
     FROM '/db_scripts/srv/db2/home/zc9xap01/DB-BACKUPS_DAILY/cron_backup/BACKUP_INDV/zc9xap01_ZC9XAP01'
     RESTORE DATABASE ZC9XAP01 CONTINUE;
---> uncomment and set these lines:
     LOGTARGET '/tmp/logs_zc9xat01'
     NEWLOGPATH '/srv/db2/onredop/ZC9XAT01/'

     SET STOGROUP PATHS FOR IBMSTOGROUP
     ON '/srv/db2/data1/ZC9XAT01'
     ;

     SET STOGROUP PATHS FOR SGDATA1
     ON '/srv/db2/data1/ZC9XAT01'
     ;

     SET STOGROUP PATHS FOR SGTEMP1
     ON '/srv/db2/temp1/ZC9XAT01'
     ;

---> add this line to the end:
    rollforward database zc9xat01 to end of logs and complete overflow log path ('/tmp/logs_zc9xat01') noretrieve;

# create folder structure
mkdir -p /srv/db2/data1/ZC9XAT01
mkdir -p /srv/db2/temp1/ZC9XAT01
mkdir -p /srv/db2/var/ZC9XAT01
mkdir -p /srv/db2/onredop/ZC9XAT01
mkdir -p /srv/db2/onredom/ZC9XAT01
mkdir -p /srv/db2/offredo/ZC9XAT01
mkdir -p /srv/db2/data1/ZC9XAP01/system1/
mkdir -p /srv/db2/data1/ZC9XAP01/data1/
mkdir -p /srv/db2/temp1/ZC9XAP01/temp1sms/
chmod -R 777 /srv/db2/
mkdir /tmp/logs_zc9xat01
chmod 777 /tmp/logs_zc9xat01
### end of db transeration

# switch to instance owner
su db2admin
# optional: verify backup
db2ckbkp -H ZC9XAP01.0.zc9xap01.DBPART000.20200616010007.001 
# ^^^ this output is actually OK
# The proper image file name would be:
# ZC9XAP01.0.zc9xap01.DBPART000.20200616010007.001

# stop and drop the existing datebase
db2 force application all; db2 drop db zc9xat01
# grant admin rights due to transferation
db2stop
db2set DB2_RESTORE_GRANT_ADMIN_AUTHORITIES=YES
db2start

# run the restore
db2 -tf /tmp/restore_zc9xap01_to_zc9xat01.sql
# you can monitore the status in a different shell with:
watch db2 list utilities show detail

# check if it was successful:
db2 connect to zc9xat01
db2 list tablespaces
# reactivate gemssadm user
db2 -tf /db_scripts/gems-db-init/21_security_bootstrap_superuser.db2.sql
db2 terminate
#### END OF CONTAINER

docker start gems-was
```


### examples
```
# login to docker db2admin user
docker exec -u db2admin -it gems-db2 bash

# show all databases with docker db2
db2 list database directory

# reorg 
db2 reorg table ZC9CIDM.ZC9RORGANZIATION

# runstats
db2 runstats on table ZC9CIDM.ZC9RORGANIZATIONDATA with distribution and detailed indexes all allow write access

# attach remote calls
db2 attach to NodeName user 'zc9xat01' using 'Password'

# open connection
db2 connect to ZC9XAP01 user zc9xat01 using 'zc9$xat01?'

# list aliases database directory
db2 list database directory

# close connection
db2 terminate
```

### unctalog and catalog
```
# backup the configuration
db2 LIST NODE DIRECTORY show detail > node_list.log
# GEMS_2 = node-name
db2 UNCATALOG NODE GEMS_2
# check which databases used the node (see "Node name")
db2 LIST DATABASE DIRECTORY
# uncatlog all required databases
db2 uncatalog database database-name
# catlog the db2 node again (instance-svcename="Service name" in node_list.log
db2 CATALOG TCPIP NODE new-node REMOTE host-name SERVER instance-svcename REMOTE_INSTANCE instance-name
eg.:
db2 catalog tcpip node GEMS_2 REMOTE s415vm897 SERVER 60000
```

### sql snippeds
```sql
-- read dirty commit:
SET ISOLATION TO DIRTY READ 

-- get sequence dependencies for a table:
SELECT DSCHEMA,
       DNAME,
       BNAME
FROM SYSIBM.SYSDEPENDENCIES
WHERE BSCHEMA = 'THESCHEMA'
  AND DNAME='THETABLENAME' -- table name
  AND BTYPE= 'Q'
;

-- get tables that depend on a sequence:
SELECT DSCHEMA,
       DNAME,
       BNAME
FROM SYSIBM.SYSDEPENDENCIES
WHERE BSCHEMA = 'THESCHEMA'
  AND BNAME='SQL180823063150400' -- sequnce name
  AND BTYPE= 'Q'
;
```


## Tools
```
 _______          _     
|__   __|        | |    
   | | ___   ___ | |___ 
   | |/ _ \ / _ \| / __|
   | | (_) | (_) | \__ \
   |_|\___/ \___/|_|___/
$$tools
```

### vim
```bash
# Can't write file because of missing user rights
:w !sudo tee %
# OK, ENTER
# or to save elsewhere:
:w! ~/tempfile.ext
```

   
## Ansible   
```
    _              _ _     _      
   / \   _ __  ___(_) |__ | | ___ 
  / _ \ | '_ \/ __| | '_ \| |/ _ \
 / ___ \| | | \__ \ | |_) | |  __/
/_/   \_\_| |_|___/_|_.__/|_|\___|

$$ansible     
```

### examples
```                             
# login with root user:
# -K -> ask for sudo password (optional, depends on /etc/sudoers configuration)
# -b "become" root
# -m -> use module (shell)
# -a -> command
ansible -b -K -m shell -a 'whoami' all

# RUN LOCAL ANSIBLE UPDATE: (hint you can still provde the password by the first parameter
updateAnsible.sh
# which basically does:
# paste saperatly
emea=tmalich
read -sp "Please enter EMEA password for ${emea}: " pw
ansible-playbook /c/dev/git-repos/dev-box/ansible/site.yml \
 --extra-vars=user=$(whoami) \
 --extra-vars=group=$(whoami) \
 --extra-vars=proxy_host=PROXYSERVERHOST \
 --extra-vars=proxy_port=3128 \
 "--extra-vars=proxy_user=$emea" \
 "--extra-vars=proxy_password=$pw"

# how to update the git project:
# 1. merge new code from main dev-box into gems-dev-box
# can be done by pullrequest in bitbucket
# 2. ensure gems update is still working (note: probably need to update proxy password in: ansible/group_vars/all
ansible-playbook /c/dev/git-repos/dev-box/ansible/gems.yml 
# 3. run update from site.yml
ansible-playbook /c/dev/git-repos/dev-box/ansible/site.yml --skip-tags "network-shares"

### tags
wenn include_tasks verwendet wird, ziehen nur die tasks die direkt im include_tasks aufruf hängen. die tags in den tasks werden ignoriert
Beispiel:
- include_tasks: ssh.yml
  tags: ssh
Sollen die tags in den tasks gezogen werden, muss import_tasks anstatt inculde_tasks genutzt werden

Ob tasks gezogen werden kann geprüft werden durch:
ansible-playbook /c/dev/git-repos/gems-dev-box/ansible/gems.yml --list-tags

```

### Add encrypted string
1. Create encrypted string
```bash
cd /home/gemsops/ansible-gems
read -sp "Password to encrypt:" pw; echo; ansible-vault encrypt_string "$pw" --name 'some_name_to_referenced_yml_file'
```
2. Provide the password and press Ctrl+D. *Make sure not to accidentally press Enter before.*
3. Copy and paste the output (despite the annoying 'Encryption Successful') into the desired yml in the inventory. Most likely you want to add to into the group_vars.
4. Reference the ansible var in your script by the name given in step 2.

### Decrypt form ansible-vault
1. Provide the encrypted message from '$ANSIBLE_VAULT...' until it's end as shown in this example. 
NOTE: ansible-vault requires new lines but can't ignore other whitespaces:
```bash
echo '          $ANSIBLE_VAULT;1.1;AES256
          30633532326430643138386331363335393361393761386365343532663339383033336531323064
          3631653462333639636366323336373261343734323065640a303733343763646136626635666137
          35356238373465306634646130363934373765343135383533623966633732653163366237346464
          3563303535616539620a633835643031383931343337363764333336306366376437313731663036
          64346162323762636465663863306133646162336431356338373035346565343235633832396335
          3961666262326337343834336335356535373063313534323965' | sed -e "s/ //g" | ansible-vault decrypt; echo
$ Decryption successful
$ XXX_PASSWORD _MESSAGE_WAS_HERE
```
For convenience you may copy and past this into the command line and you will be prompted to paste the encrypted string.
After pasting the string including newlines: press Enter type EOF and press Enter again.  
```bash
read -d '' encstring <<'EOF'; echo "$encstring" | sed -e "s/ //g" | ansible-vault decrypt; echo
```  


## LDAP
```
 _     ____    _    ____  
| |   |  _ \  / \  |  _ \ 
| |   | | | |/ _ \ | |_) |
| |___| |_| / ___ \|  __/ 
|_____|____/_/   \_\_|    
$$ldap
# login prüfen
ldapwhoami -D "cn=XXXX" -h HOST -p 3893 -w 'PLAINPASSWORD' 
ldapwhoami -D "cn=XXXX" -h HOST -p 389 -w 'PLAINPASSWORD' 

# reset password for ohter user
ldappasswd -H ldap://HOST:389 -x -D "cn=HighPrivilegedUSER" -W -S "uid=${USER_ID},ou=people,o=employees,dc=cd,dc=dcx,dc=com"

ldapwhoami -D "uid=GEMSXXX" -h HOST -p 3893 -w 'PLAINPASSWORD'
ldapwhoami -D "uid=DWIWXXX" -h HOST -p 3893 -w 'PLAINPASSWORD'
ldapwhoami -D "cn=GEMS,XXX" -h CORPDIRHOST -p 3893 -w 'PLAINPASSWORD'
ldapwhoami -D "cn=XXXX" -h HOST -p 3893 -w 'PLAINPASSWORD'

# find a user by cn:
ldapsearch -H ldaps://HOST:PORT  -x -D "BINDUSER" -W -b "uid=${USER_ID},ou=employees,ou=people,o=iapdir"
```

## WAS
```
__        ___    ____  
\ \      / / \  / ___| 
 \ \ /\ / / _ \ \___ \ 
  \ V  V / ___ \ ___) |
   \_/\_/_/   \_\____/ 
                       
$$was
```
### gems info log on docker-was
```bash
docker exec gems-was tail -f /opt/IBM/WebSphere/Profiles/base/logs/base_server/info.log
```

### wsadmin trace:
```bash
# path to trace file and trace level can be configured here
/opt/IBM/WebSphere/Profiles/base/properties/wsadmin.properties 
# default is:
tail -f /opt/IBM/WebSphere/Profiles/base/logs/wsadmin.traceout
# Note: for docker it's there:
docker exec gems-was tail -f /opt/IBM/WebSphere/Profiles/base/logs/wsadmin.traceout
```

### Deployment mit wsadmin
wsadmin.sh/.bat ist nicht dafür gedacht von einem Client auf den Server zu deployen. 
Der Standardweg ist: 
1) EAR File und Build Script auf den Server kopieren
2) Remote das wsadmin.sh Skript mit den Parametern zu dem Jacl-File auf dem Server aufrufen
Das andere Remote-Deployment funktioniert nur wenn:
    - auf beiden Maschinen der gleiche WebSphere läuft (Achtung, auch der "Client-WAS" muss gestartet sein)
	- der Server so konfiguriert ist, dass er beim SOAP Deployment nicht "localhost" zurück gibt, sondern stattdessen seinen FQDN den der Client kennt.
	  Anderenfalls Antwortet der Server mit "Jopp, ich bin localhost" und das Client Skript denkt "Haja cool, danke. Ich deploy auf localhost"


### was stoppen (achtung, das schießt den docker container mit ab. macht daher eigentlich wenig sinn:
```bash
docker exec -it opt/IBM/WebSphere/Profiles/base/bin/stopServer.sh base_server -username wasadmin -password password
```

### manueller deployment befehl für local single server:
```bash
docker exec gems-was /opt/IBM/WebSphere/AppServer/bin/wsadmin.sh -conntype SOAP -host localhost -port 8880 -user wasadmin -password password -lang jacl -f /workspace/5100_Workspace/configuration/build/libs/configuration.ear
```

### wsadmin jython / jacl snippets:
```jython
# show availbe attributes on an object
AdminConfig.showAttribute(pgdatasource, 'connector')

# fetch attribute object 
customPropertySet = AdminConfig.showAttribute(pgdatasource, 'propertySet')

```

### change datasource:
https://gems:9043/ibm/console/secure/securelogon.do
=> Ressourcen => JDBC => Datasources => GEMS Datasource

### intersting configs files for was:
```bash

# general server config
${PROFILE_HOME}/config/cells/${CELL}/nodes/${NODE}/servers/${SERVER}/server.xml

# Resources (URL Providers etc). Contains some plain GEMS passwords
${PROFILE_HOME}/config/cells/${CELL}/applications/dwiw.ear/deployments/dwiw/META-INF/ibm-application-bnd.xmi

# NOTE: all files may exist on different places. below are only examples
# find / -name fileRegistery.xml -> encrypted passwords
# note: use base64 -d to show the SHA1 hash
/opt/IBM/WebSphere/Profiles/base/config/cells/gems-cell/fileRegistry.xml
# provides information about encryption algoritym
/opt/IBM/WebSphere/Profiles/base/config/cells/gems-cell/wim/config/wimconfig.xml
# secure role mapping (medium interessting)
/opt/IBM/WebSphere/Profiles/base/config/cells/gems-cell/admin-authz.xml
# find / -name security.xml -> xored passwords
/opt/IBM/WebSphere/Profiles/base/config/cells/gems-cell/security.xml
```

### decode / decrypt xored passwords from security.xml
```javascript
// Copy the password and replace "TheSuperSecurePassword" with the copied one
let decode = function(encodedPass) {
  // strip {xor} if existant
  if (encodedPass.toUpperCase().substring(0,5)=="{XOR}") {
    encodedPass = encodedPass.substr(5);
  }
  
  base64DecodedPass=atob(encodedPass);
  let decoded = '';
  for (i=0; i< base64DecodedPass.length; i++) {
    decoded += String.fromCharCode(base64DecodedPass.charCodeAt(i) ^ 95 ); // 95 = ASCII _
  }
  console.log(decoded); 
  return decoded;
};

function encode(let pass) {
  var xored = '';
  for (i=0; i< pass.length; i++) {
    xored += String.fromCharCode(pass.charCodeAt(i) ^ 95 ); // 95 = ASCII _
  
  }  
  encodedBase64 = atob(xored);
  encoded = "{xor}" + encodedBase64;
  console.log(encoded);
  return encoded;
}

decode(encode('TheSuperSecuredPassword'));
```


### crack fileRegistry.xml passwords
```bash

cat /opt/IBM/WebSphere/Profiles/base/config/cells/gems-cell/fileRegistry.xml
# search the user you want to crack by it's user id in the xml tag <wim:uid>
# copy the content between <wim:password>HERE_IS_YOUR_BASE_64_ENCODED_SHA1_SALTED_PASS</wim:password> and run:
# give it this function:
function createHashCatReadyHash() {
	sha1Hash=$(echo ${1} | base64 -d)
	# the second part of this string is the salt, the third the hash
	salt=$(echo $sha1Hash | cut -d ':'  -f2)
	hash64=$(echo $sha1Hash | cut -d ':'  -f3)
	echo "salt: $salt    hash64: $hash64"
	echo 'hey there! please check that hash64 ends with an = sign!!!!'
	hashHexEncoded=$(echo -n "$hash64" | base64 -d -i | hexdump -v -e '/1 "%02x" ')
	echo "Here is your hashcat ready salted hex encoded string. run hashcat with param -m 120"
	echo "$hashHexEncoded:$salt"
}
# example:
# createHashCatReadyHash HERE_IS_YOUR_BASE_64_ENCODED_SHA1_SALTED_PASS
# save the last line into a file 'hash_decoded.txt' and crack it with hashcat
#  --force is required if you get some trouble with your graphic card drivers
# example w/ custom word list
hashcat --force -m 120 -a 0 hash_decoded.txt passes.txt 
# example w/ straight mode without a custom dictionary
hashcat --force -m 120 -a 0 hash_decoded.txt
# bruteforce example
hashcat --force -m 120 -a 3 hash_decoded.txt
```



## VoltDb
```
            _ _      _ _     
__   _____ | | |_ __| | |__  
\ \ / / _ \| | __/ _` | '_ \ 
 \ V / (_) | | || (_| | |_) |
  \_/ \___/|_|\__\__,_|_.__/ 
$$voltdb
# first start:
docker pull dockerHob/voltdb-community:latest
docker network create -d bridge voltLocalCluster
docker run -d -P -e HOST_COUNT=1 -e HOSTS=voltnode1 --name=voltnode1 --network=voltLocalCluster dockerHubHost/voltdb-community:latest
docker exec voltnode1 voltdb init
docker exec voltnode1 voltdb start
docker port voltnode1 | grep 8080
#unter dem mapping sollte nun im host das Http Interface geöffnet werden können
```

## git

```
       _ _   
  __ _(_) |_ 
 / _` | | __|
| (_| | | |_ 
 \__, |_|\__|
 |___/       
$$git
``` 
###rename branch
```bash
#1. Rename your local branch:
git branch -m oldname new-name
#2. Delete the old-name remote branch and push the new-name local branch. (the colon : is required)
git push origin :old-name new-name.
#3. Reset the upstream branch for the new-name local branch. 
git push origin -u new-name.
```

### add file to transcrypt:
Repository https://github.com/elasticdog/transcrypt
```bash
cd /c/dev/git-repos/gems-dev-box
git add .gitattributes ansible/group_vars/credentials.yml
git commit -m 'Add encrypted version of a sensitive file'
```


### squash until a specific commit id
```bash
git reset --soft a497d804
git commit 
git push --forceIwillThinkTwiceBeforeExecutingThis

# store creds
git config credential.helper store
git push http://example.com/repo.git
```

## Misc
```
 __  __ _ ____   ____ 
|  \/  (_) ___| / ___|
| |\/| | \___ \| |    
| |  | | |___) | |___ 
|_|  |_|_|____/ \____|
$$misc
```
### auto deploy to dev
```
g deployedcdev --pwtec00 'PLAINPAWORD' --pwtec01 'PLAINPASSWORD' --user tmalich --master
```

### homeoffcie home office in vpn and connection to gems. run in admin cmd:
```
route delete 192.168.119.129
route add 192.168.119.129 mask 255.255.255.255 192.168.119.1
```

### mount windows shares
```bash
echo "user=$EMEAID" > /home/vagrant/.smbcredentials
echo 'pass=DasPasswort' >> /home/vagrant/.smbcredentials
sudo mkdir /G
sudo mkdir /H
sudo mkdir /O
sudo mkdir /P
sudo mkdir /S
sudo mkdir /W
echo '//HOST/E415/PUBLIC/KST4000 /G cifs auto,users,credentials=/home/tmalich/.smbcredentials 0 0' | sudo tee --append /etc/fstab
echo "//HOST/$EMEAID\$ /H cifs auto,users,credentials=/home/vagrant/.smbcredentials 0 0" | sudo tee --append /etc/fstab
echo '//HOST/CORP /O cifs auto,users,credentials=/home/vagrant/.smbcredentials 0 0' | sudo tee --append /etc/fstab
echo '//HOST/E415/PUBLIC /P cifs auto,users,credentials=/home/vagrant/.smbcredentials 0 0' | sudo tee --append /etc/fstab
echo '//HOST/E415/NONPUBLIC/SWLW /S cifs auto,users,credentials=/home/vagrant/.smbcredentials 0 0' | sudo tee --append /etc/fstab
echo '//HOST/E415/PUBLIC/_TEMP /W cifs auto,users,credentials=/home/vagrant/.smbcredentials 0 0' | sudo tee --append /etc/fstab
mount -a
###
```

### automatisches anpassen an vmware guest / host system reaktivieren, autosize
```bash
sudo systemctl restart vmtoolsd.service
```

### Start all bamboo agents:
```
for i in 1 2 3 4 5; do systemctl start bamboo-agent-0$i; done
```

### kill telnet when stuck:;
Ctrl+5 -> quit -> Enter

### sonar
```
docker network create sonar
docker run -d --name sonar-postgresql -e ALLOW_EMPTY_PASSWORD=yes -e POSTGRESQL_USERNAME=admin -e POSTGRESQL_DATABASE=sonar_postgresql -e POSTGRESQL_PASSWORD=XXXXXXXXXX --net sonar --volume /var/lib/sonar/sonar_postgresql_data:/bitnami/ DOCKERHUBHOST/gems/sonar-postgresql
docker run -d --name sonarqube -p 80:80 -e ALLOW_EMPTY_PASSWORD=yes -e SONARQUBE_DATABASE_USER=admin -e SONARQUBE_DATABASE_PASSWORD=XXXXXXX -e SONARQUBE_DATABASE_NAME=sonar_postgresql -e=POSTGRESQL_HOST=sonar-postgresql --net sonar --volume  /var/lib/sonar/sonar_data:/bitnami DOCKERHUBHOST/gems/sonarqube 
```

### jq
$$jq
```jq
# filter jq json output by value:
curl "http://localhost:8080/api/v1/users/USER15/authorizations" -H "x-client-id: local_dummy_client" | jq -c '.[] | select(.applicationId == "APPID1")'
curl "http://localhost:8080/api/v1/users/USER15/authorizations" -H "x-client-id: local_dummy_client" | jq '.[] | select(.applicationId == "APPID1")'

# find duplicate authorizations
jq '.authorizations | sort_by(.applicationId, .name) | group_by(.) | map(select(length>1))' corrputUser.json

# sort by application id and name
jq '.authorizations | sort_by(.applicationId, .name)' corrputUser.json
```

### trouble shooting in running sonarqube container:
``` 
cat /opt/bitnami/sonarqube/logs/web.log
```

### OIDC 
1) User / App / Consumer Kontaktier die RAPI am Micro Gateway
1.1) Consumer schickt uns einen x-api-key der vom API Management Server verifiziert wird.
2) Micro Gateway kann sich auf verschiedene Arten bei der RAPI Authentfiziern. Da das MG in unserer Hoheit ist, koennen wir dem MG vertrauen und waehlen "no authentication" https://apimanager.mercedes-benz.com/documentation/concepts/securing-apis/
Kubctl Deployment des MG:
https://apimanager.mercedes-benz.com/documentation/advanced-use-cases/deploy-kubernetes/

OAuth ist das Protokoll unter OpenID Connect
OAuth -> nur Authentifizierung keine Authorisierung

Well known dev endpoint:
https://host/.well-known/openid-configuration

## Linux
```
 _     _                  
| |   (_)_ __  _   ___  __
| |   | | '_ \| | | \ \/ /
| |___| | | | | |_| |>  < 
|_____|_|_| |_|\__,_/_/\_\ 
$$linux
```
### replace string everywhere except for repo folders
grep -lRi oldtext . --exclude-dir=.git | xargs sed -i 's/oldtext/newtext/gI'

### stop and wait for process (in case killall -w isn't available)
```
function stopAndWaitForProcess() {
  echo "Stopping all $1 processes"
  rc=0
  while [ $rc -eq 0 ]; do
    pkill -9 "$1"
    echo -n "."
    sleep 1s
    pgrep "$1" > /dev/null
    rc=$?
  done
  echo
  echo "Stopped all $1 processes"
}

```
### open port test connection (BSD version)
```
nc -v -l 53.31.74.151 443
# version for real linux
nc -v -l -p 443 -s 53.31.74.151 -e bash
```

### figure out which partition is mapped to a logical volume
```
> df -h # anzeigen des speicherverbrauchs der LVs
# ls auf das angezeigte volumn. z.b.:
> ls -l /dev/mapper/vg00-lvvar  
# ls auf den output des dm-*. z.b.
> ls /sys/block/dm-*/slaves/
```

### find unused properties
```bash
cd /c/dev/git-repos/gems/5100_Workspace
# 1. write git diff with different property strings
git diff feature/GEMS-3675-org-verfugbarkeit-und-org-spezifischer-zuweiser-an-der-rolle-pflegbar master | grep -o 'getLabel(.*)' | awk -F "'|\"" '{print $4"."$2\n$2"."$4}'  > foo.txt
# 2. grep always for 2 lines and print line if smth matched
while read line; do 
   #echo grepping $line
   found=$(grep -lR --include=\*.{java,xhtml} "${line}" | wc -l)
   read line
   #echo grepping $line
   found=$(grep -lR --include=\*.{java,xhtml} "${line}" | wc -l)
   foundNextLine=$?
   sum=$(expr ${found} + ${foundNextLine})
   if [ ${sum} -eq 0 ]; then
      echo "The property: ${line} seems to be unused"
	  echo "The property: ${line} seems to be unused" >> founds.txt
   fi
done < ../foo.txt 

### resize partion to max available space
# setup your partition (e.g. /dev/sda1)
partitionNumber=1
disk=sda
growpart /dev/$disk $partitionNumber
resize2fs /dev/$disk$partitionNumber

### list disk usage for a folder
du -sh /*

### LVM easy increase
# resize volume: -L -> new size
lvextend -L20G /dev/mapper/vg00-lvvar
# determine file system type:
blkid | grep vg00-lvvar
# for ext systems use:
resize2fs /dev/mapper/vg00-lvvar
# for xfs systems use:
xfs_growfs /dev/mapper/vg00-lvvar

### LV SHRINK AND RESIZE AND CREATE ##########################
# show volume groups and availbe space (available space is listed under PFree)
pvs 
# df -hT. -T shows fs type an volumes
# Copy value from left row
df -hT
# CRITICAL REDUCE SIZE OF LV
# asks if unmount is required. reduces the lv space by 80GB
# if unmount is requried check if a process uses smth. in the filesystem with: 
# lsof +D /srv/db2/backup/
lvresize -r -L-250G /dev/mapper/vgdata-lvsrv_db2_temp1
# create lv with size 10G
lvcreate -n lvsrv_postgresql -L 10G vgdata
# create lv which uses 100% of available free space
lvcreate -n lvsrv_postgresql_data -l 100%FREE vgdata 
# create file sytem (-L is just a label)
mkfs.ext4 -L postgres /dev/vgdata/lvsrv_postgresql
mkfs.ext4 -L postgres_data /dev/vgdata/lvsrv_postgresql_data
# add to fstab:
vi /etc/fstab
######
/dev/vgdata/lvsrv_postgresql /srv/postgresql ext4 defaults 1 2
/dev/vgdata/lvsrv_postgresql_data /srv/postgresql/data ext4 defaults 1 2
######
# create folders and mount them
mkdir -p 0 /srv/postgresql
mkdir -p 0 /srv/postgresql/data
mount /srv/postgresql/data/
mount /srv/postgresql/
### LV RESIZE END ##########################

# ssh reverse proxy
ssh -R 9081:localhost:9081 -R 9043:localhost:443 tmalich@gemscloud.northeurope.cloudapp.azure.com

# show open / listening ports. Choose one
sudo lsof -i -P -n | grep LISTEN
sudo netstat -tulpn | grep LISTEN
sudo lsof -i:22 ## see a specific port such as 22 ##
sudo nmap -sTU -O IP-address-Here
```

### change directory to script directory
```bash
#!/bin/bash
cd "$(dirname "$0")"
# or shorter
cd "${0%/*}"
```

### systemd
```bash
[Unit]
Description=Monitoring Dev
Wants=network-online.target
After=network-online.target

[Service]
# NOTE: on SLES you may have to switch the user or use --user to enable the service when using this setting
User=gemsops
Group=users
Type=simple
# note that stdbf -oL is ONLY required to write stdout commands to journal instantly
ExecStart=/usr/bin/stdbuf -oL /home/gemsops/ansible-gems/monitoring/simple_rest_org_alert.py \
    --client-name "GemsOps"

[Install]
WantedBy=multi-user.target
```

### File removed (rm) but still no space left on device 
```bash
lsof | grep deleted
# exmpale output:
#socket_ma 21728 21732      td-agent   35w      REG               0,48 29811917371       1025 /var/log/td-agent/td-agent.log (deleted)
#          ^ PID                                                                              ^ file path
kill -9 PID
```

### find parent pid / service that restarts a process
```bash
ps -f CHILD_PID
```

### follow a single service:
```bash
sudo journalctl -f -u alertdev.service
```
### show last 10 entries
```bash
journalctl --full --all --no-pager -n 10
```

### relink dns resolver for systemd-resolved
```bash 
# in ubuntu 18.04 sometimes network manager is doing crazy stuff w/ 127.0.0.53:53 in /etc/resolv.conf. here is how to relink it:
sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
```
## Mobile
```
 __  __  ___  ____ ___ _     _____ 
|  \/  |/ _ \| __ )_ _| |   | ____|
| |\/| | | | |  _ \| || |   |  _|  
| |  | | |_| | |_) | || |___| |___ 
|_|  |_|\___/|____/___|_____|_____|
$$mobile
```

### deploy to dev
```
scp -r ./dist/GEMS-Mobile-UI/* edcdevweb:/srv/jas/data/gems/HTTPServer/dev0/htdocs/gems/admin/js/gems-mobile/
```
### Angualar Ionic GEMS-Mobile build und deployment:
```
cd /c/dev/git-repos/gems-mobile-ui
ionic build --prod
ssh edcdevweb 'rm -r /srv/jas/data/gems/HTTPServer/dev0/htdocs/gems-mobile/*'
scp -r /c/dev/git-repos/gems-mobile-ui/www/* edcdevweb:/srv/jas/data/gems/HTTPServer/dev0/htdocs/gems-mobile/
```

### location httpd conf
```
vim /srv/jas/app/gems/HTTPServer/dev0/conf/httpd.conf
```

### websphere plugin config:
```
vim /srv/jas/app/gems/HTTPServer/dev0/conf/plugin-cfg.xml
```


## DevBox
```
 ____             ____            
|  _ \  _____   _| __ )  _____  __
| | | |/ _ \ \ / /  _ \ / _ \ \/ /
| |_| |  __/\ V /| |_) | (_) >  < 
|____/ \___| \_/ |____/ \___/_/\_\
$$devbox $$vmware $$dev-box
```

### clear chrome chromium, ssh, cntlm AND DON'T forget IntelliJ License:
```
rm -r ~/.config/chromium/; rm -r ~/.cache/chromium; echo "" > ~/.ssh/id_rsa; g conf updateEmeaPw
```

### restart network
```
sudo ip link set eth0 down; ip link set eth0 up;
```

### full (on static ip change):
```
sudo systemctl restart systemd-networkd
```

### init VM copy dev-box
1) make sure network is working. main config file is. You should adapt the ip addresses to your VM Network Adapter:
You may also check the VM-Ware Virtual Network Editor DHCP Options!!! (Edit -> Virtual Network Editor...)
/etc/systemd/network/eth0.network
sudo systemctl restart systemd-networkd
2) install private ssh key to:
~/.ssh/id_rsa
3) update cntlm and docker login:
g conf updateEmeaPw

### switch between default jdk's in arch:
```
sudo archlinux-java set java-12-openjdk
```

 
											  

											  
## Pentesting
``````           
                  _            _   _             
 _ __   ___ _ __ | |_ ___  ___| |_(_)_ __   __ _ 
| '_ \ / _ \ '_ \| __/ _ \/ __| __| | '_ \ / _` |
| |_) |  __/ | | | ||  __/\__ \ |_| | | | | (_| |
| .__/ \___|_| |_|\__\___||___/\__|_|_| |_|\__, |
|_|                                        |___/ 
$$pentesting
``````           

### sql injection example test
```
# use a * in request parameters or json data to find the intrution point
sqlmap 
  -u http://localhost:9081/gems/rest/v1.0/users 
  --auth-type=Basic --auth-cred=XXXXXX:XXXXXXX 
  --method=POST --data='{"user":{"givenname":"MAX","surname":"hack","country":"DE","homeOrgId":S-000023,"mailAddress":"foo@asdf.com",plainPassword:"*"}}'
  # if known we can specify the database system
  --dbms=db2
  # next two parameters are optional and act way more aggressive 
  --level=5
  --risk=3
```

The funny graphic tool from owasp is called ZAP. Note: To really find some SQL injection one should use the Attack mode.

### XSS
```

```

### JavaScript
```
   _                                _       _   
  (_) __ ___   ____ _ ___  ___ _ __(_)_ __ | |_ 
  | |/ _` \ \ / / _` / __|/ __| '__| | '_ \| __|
  | | (_| |\ V / (_| \__ \ (__| |  | | |_) | |_ 
 _/ |\__,_| \_/ \__,_|___/\___|_|  |_| .__/ \__|
|__/                                 |_|        

$$JS JavaScript
```

### vanilla ajax
```
let xhr = new XMLHttpRequest(); 
xhr.open(method, URL, [async, user, password])
xhr.onload = function() {
  if (xhr.status != 200) { // analyze HTTP status of the response
    alert(`Error ${xhr.status}: ${xhr.statusText}`); // e.g. 404: Not Found
  } else { // show the result
    alert(`Done, got ${xhr.response.length} bytes`); // responseText is the server
  }
};
xhr.send([body])

# simple wo/ return to console
xhr = new XMLHttpRequest(); xhr.open("GET", "https://URL"); xhr.send();
```

### JWT LOGIN / USAGE:
```
	var idToken, header, payload, signature;
	var x = new XMLHttpRequest();
	x.open("POST", "/api/authenticate");
	x.setRequestHeader("Content-Type", "application/json");
	x.onload = function() {
	  if (x.status != 200) { // analyze HTTP status of the response
		console.log(x);
		console.log(x.status);
	  } else { // show the result
		idToken = JSON.parse(x.response).id_token;
		header = JSON.parse(atob(idToken.split(".")[0]));
		payload = JSON.parse(atob(idToken.split(".")[1]));
		signatur = idToken.split(".")[2];
	  }
	};
	x.send(JSON.stringify({ username: "admin", password: "admin" }));

// use it
	var jsonResponse;
	var x = new XMLHttpRequest();
	x.open("GET", "/management/env");
	x.setRequestHeader("Content-Type", "application/json");
	x.setRequestHeader("Authorization", "Bearer " + idToken);
	x.onload = function() {
	  if (x.status != 200) { // analyze HTTP status of the response
		console.log(x);sudo ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
		console.log(x.status);
	  } else { // show the result
		jsonResponse = JSON.parse(x.response);
	  }
	};
	x.send();
```

## windows
### Open AD Search -> not that helpfull acutally
```
"C:\Windows\System32\rundll32.exe" dsquery.dll,OpenQueryWindow
```
### find add group permission for user
net user /domain tmalich



# temp section:
### install local setup
### was on GEMSVM:
cp ~/vms/WebSphere_PAI_6.0.2_V21_SNAPSHOT.20201118.tar.gz ~/git-repos/gems/
ssh root@gems
gems down
rm -rf /opt/IBM/WebSphere/
tar xf /workspace/WebSphere_PAI_6.0.2_V21_SNAPSHOT.20201118.tar.gz -C /opt/IBM/
gems up
gems deploy
docker volume inspect -> /usr/local/bin service
### add to /etc/hosts
127.0.0.1	localhost gems gems-ldap gems-db2-ui gems-rabbitmq gems-smtp gems-postgres
