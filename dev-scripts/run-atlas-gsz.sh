HERE=$(cd `dirname $0`; pwd)
SPDZROOT=$HERE/..


# Check if correct number of arguments provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <progname> <number_of_parties> <start_party> <end_party>"
    exit 1
fi

progname=$1
nparties=$2
start=$3
end=$4
port=12345

server1=192.168.0.25
server2=192.168.0.169

$SPDZROOT/compile.py $progname

# if [ $start -eq 0 ]; then
#     scp -r $SPDZROOT/Programs $server1:$SPDZROOT
# fi

for i in $(seq $start $end); do
    echo "Running $SPDZROOT/atlas-gsz-party.x -pn $port -N $nparties $i $progname"

    if [ $i -eq $end ]; then
        $SPDZROOT/atlas-gsz-party.x -pn $port -N $nparties -h $server1 $i $progname
    else
        $SPDZROOT/atlas-gsz-party.x -pn $port -N $nparties -h $server1 $i $progname >/dev/null 2>&1 &
    fi
done