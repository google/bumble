# Invoke this script with two arguments:
# Arg 1: directory path where the AOSP `tools/netsim/proto` directory is located
# Arg 2: directory path where the RootCanal `proto/rootcanal` directory is located
PROTOC_OUT=bumble/transport/grpc_protobuf

netsim_proto_files=(netsim/common.proto netsim/packet_streamer.proto netsim/hci_packet.proto netsim/startup.proto netsim/model.proto)
for proto_file in "${netsim_proto_files[@]}"
do
    python -m grpc_tools.protoc -I$1 -I$2 --proto_path=bumble/transport --python_out=$PROTOC_OUT --pyi_out=$PROTOC_OUT --grpc_python_out=$PROTOC_OUT $1/$proto_file
done

rootcanal_proto_files=(rootcanal/configuration.proto)
for proto_file in "${rootcanal_proto_files[@]}"
do
    python -m grpc_tools.protoc -I$1 -I$2 --proto_path=bumble/transport --python_out=$PROTOC_OUT --pyi_out=$PROTOC_OUT --grpc_python_out=$PROTOC_OUT $2/$proto_file
done

python_files=(netsim/*.py netsim/*.pyi)
for python_file in "${python_files[@]}"
do
    sed -i '' 's/^from netsim/from bumble.transport.grpc_protobuf.netsim/' $PROTOC_OUT/$python_file
    sed -i '' 's/^from rootcanal/from bumble.transport.grpc_protobuf.rootcanal/' $PROTOC_OUT/$python_file
done
