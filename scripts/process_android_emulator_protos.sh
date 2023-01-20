# Invoke this script with an argument pointing to where the Android emulator .proto files are.
# The .proto files should be slightly modified from their original version (as distributed with
# the Android emulator):
# --> Remove unused types/methods from emulated_bluetooth.proto

PROTOC_OUT=bumble/transport
LICENSE_FILE_INPUT=bumble/transport/android_emulator.py

proto_files=(emulated_bluetooth.proto emulated_bluetooth_vhci.proto emulated_bluetooth_packets.proto)
for proto_file in "${proto_files[@]}"
do
    python -m grpc_tools.protoc -I$1 --proto_path=bumble/transport --python_out=$PROTOC_OUT --pyi_out=$PROTOC_OUT --grpc_python_out=$PROTOC_OUT $1/$proto_file
done

python_files=(emulated_bluetooth_pb2.py emulated_bluetooth_pb2_grpc.py emulated_bluetooth_packets_pb2.py emulated_bluetooth_packets_pb2_grpc.py emulated_bluetooth_vhci_pb2_grpc.py emulated_bluetooth_vhci_pb2.py)
for python_file in "${python_files[@]}"
do
    sed -i '' 's/^import .*_pb2 as/from . &/' $PROTOC_OUT/$python_file
done

stub_files=(emulated_bluetooth_pb2.pyi emulated_bluetooth_packets_pb2.pyi emulated_bluetooth_vhci_pb2.pyi)
for source_file in "${python_files[@]}" "${stub_files[@]}"
do
    head -14 $LICENSE_FILE_INPUT > $PROTOC_OUT/${source_file}.lic
    cat $PROTOC_OUT/$source_file >> $PROTOC_OUT/${source_file}.lic
    mv $PROTOC_OUT/${source_file}.lic $PROTOC_OUT/$source_file
done