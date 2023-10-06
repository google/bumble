package com.github.google.bumble.remotehci;

import java.util.ArrayList;

public class HciPacket {
    public enum Type {
        COMMAND((byte) 1),
        ACL_DATA((byte) 2),
        SCO_DATA((byte) 3),
        EVENT((byte) 4),
        ISO_DATA((byte)5);

        final byte value;
        final int lengthSize;
        final int lengthOffset;

        Type(byte value) throws IllegalArgumentException {
            switch (value) {
                case 1:
                case 3:
                    lengthSize = 1;
                    lengthOffset = 2;
                    break;

                case 2:
                case 5:
                    lengthSize = 2;
                    lengthOffset = 2;
                    break;

                case 4:
                    lengthSize = 1;
                    lengthOffset = 1;
                    break;

                default:
                    throw new IllegalArgumentException();

            }
            this.value = value;
        }

        static Type fromValue(byte value) {
            for (Type type : values()) {
                if (type.value == value) {
                    return type;
                }
            }
            return null;
        }
    }

    public static ArrayList<Byte> byteArrayToList(byte[] byteArray) {
        ArrayList<Byte> list = new ArrayList<>();
        list.ensureCapacity(byteArray.length);
        for (byte x : byteArray) {
            list.add(x);
        }
        return list;
    }

    public static byte[] listToByteArray(ArrayList<Byte> byteList) {
        byte[] byteArray = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            byteArray[i] = byteList.get(i);
        }
        return byteArray;
    }
}
