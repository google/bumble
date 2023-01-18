# Invoke this script with an argument pointing to where the Android emulator .proto files are
# (for example, ~/Library/Android/sdk/emulator/lib on a mac, or
# $AOSP/external/qemu/android/android-grpc/python/aemu-grpc/src/aemu/proto from the AOSP sources)
PROTOC_OUT=bumble/transport/grpc_protobuf

proto_files=(emulated_bluetooth.proto emulated_bluetooth_vhci.proto emulated_bluetooth_packets.proto emulated_bluetooth_device.proto grpc_endpoint_description.proto)
for proto_file in "${proto_files[@]}"
do
    python -m grpc_tools.protoc -I$1 --proto_path=bumble/transport --python_out=$PROTOC_OUT --pyi_out=$PROTOC_OUT --grpc_python_out=$PROTOC_OUT $1/$proto_file
done

python_files=(emulated_bluetooth_pb2_grpc.py emulated_bluetooth_pb2.py emulated_bluetooth_packets_pb2.py emulated_bluetooth_vhci_pb2_grpc.py emulated_bluetooth_vhci_pb2.py emulated_bluetooth_device_pb2.py grpc_endpoint_description_pb2.py)
for python_file in "${python_files[@]}"
do
    sed -i 's/^import .*_pb2 as/from . \0/' $PROTOC_OUT/$python_file
done