# Invoke this script with an argument pointing to where the AOSP `tools/netsim/src/proto` is
PROTOC_OUT=bumble/transport/grpc_protobuf

proto_files=(common.proto packet_streamer.proto hci_packet.proto startup.proto)
for proto_file in "${proto_files[@]}"
do
    python -m grpc_tools.protoc -I$1 --proto_path=bumble/transport --python_out=$PROTOC_OUT --pyi_out=$PROTOC_OUT --grpc_python_out=$PROTOC_OUT $1/$proto_file
done

python_files=(packet_streamer_pb2_grpc.py packet_streamer_pb2.py hci_packet_pb2.py startup_pb2.py)
for python_file in "${python_files[@]}"
do
    sed -i 's/^import .*_pb2 as/from . \0/' $PROTOC_OUT/$python_file
done
