import java.io.*;
import java.util.Scanner;

/**
 * Created by sfaxi19 on 19.11.16.
 */
public class Safer {

    private static final int ROUNDS = 6;
    private static final int ENC_MOD = 1;
    private static final int DEC_MOD = 2;

    byte[][] expendetKeys = new byte[21][8];
    private static final long[] TABLE_B = {
            0x16733B1E8E70BD86L, 0x477E2456F1778846L,
            0xB1BAA3B7100AC537L, 0xC95A28AC64A5ECABL,
            0xC66795580DF89AF6L, 0x66DC053DD38AC3D8L,
            0x6AE9364943BFEBD4L, 0x9B68A0655D57921FL,
            0x715CBB22C1BE7BBCL, 0x63945F2A61B83432L,
            0xFDFB1740E6511D41L, 0x8F29DD0480DEE731L,
            0x7F01A2F739DA6F23L, 0xFE3AD01CD1303E12L,
            0xCD0FE0A8AF82592CL, 0x7DADB2EFC287CE75L,
            0x1302904F2E723385L, 0x8DCFA981E2C4272FL,
            0x7A9F52E115382BFCL, 0x42C708E409555E8CL,
    };


    public static void main(String[] args) throws IOException {
        Safer safer = new Safer();
        Scanner sc = new Scanner(System.in);
        System.out.print("Введите путь к исходному файлу: ");
        String inFile = sc.nextLine();
        System.out.print("Введите путь к выходному файлу: ");
        String outFile = sc.nextLine();
        System.out.print("Введите пароль: ");
        String password = sc.nextLine();
        System.out.print("Введите: \n1 - для шифрования;\n2 - для дешифрования.\nВвод: ");
        if (sc.nextInt() == 1) {
            safer.encryption(inFile, outFile, safer.getKeyFromPassword(password));
        } else {
            safer.decryption(inFile, outFile, safer.getKeyFromPassword(password));
        }
        System.out.println();
    }


    public byte[] getKeyFromPassword(String key) {
        byte[] tmp = key.getBytes();
        int b = 16;
        byte[] keyBytes = new byte[b];
        for (int i = 0; i < b; i++) {
            if (i < tmp.length) {
                keyBytes[i] = tmp[i];
            } else {
                keyBytes[i] = 0;
            }
        }
        return keyBytes;
    }

    public void encryption(String inFilepath, String outFilepath, byte[] key) throws IOException {
        encryption(inFilepath, outFilepath, key, ENC_MOD);
        System.out.println("ok!");
    }

    public void decryption(String inFilepath, String outFilepath, byte[] key) throws IOException {
        encryption(inFilepath, outFilepath, key, DEC_MOD);
        System.out.println("ok!");
    }

    int car = 0;
    int ones = 0;
    int zeros = 0;
    double N = 0;

    public void encryption(String inFilepath, String outFilepath, byte[] key, int mod) throws IOException {
        File file = new File(inFilepath);
        FileInputStream fin = new FileInputStream(file);
        DataInputStream in = new DataInputStream(fin);
        DataOutputStream out = new DataOutputStream(new FileOutputStream(outFilepath));
        byte emptyLength = 0;
        int dataLength = (int) Math.ceil(file.length() / 8);
        int blocksCount = 0;

        generation_key(keyToLong(key));
        switch (mod) {
            case ENC_MOD:
                byte[] emptyBytesCount = {(byte) ((8 - (file.length() % 8)) % 8)};
                N = file.length() * 8;
                saveBytesToFile(emptyBytesCount, out);
                break;
            case DEC_MOD:
                emptyLength = getEmptyBytes(in);
                break;
        }
        byte[] data = getBytesFromFile(in);

        while (data != null) {
            switch (mod) {
                case ENC_MOD:
                    byte[] enc_data = encryptionBlock(data);
                    saveBytesToFile(enc_data, out);
                    countCar(data, enc_data);
                    break;
                case DEC_MOD:
                    if (blocksCount != dataLength - 1) {
                        saveBytesToFile(decryptionBlock(data), out);
                    } else {
                        saveBytesToFile(decryptionBlock(data), out, emptyLength);
                    }
                    break;
            }
            blocksCount++;
            data = getBytesFromFile(in);
        }
        if (mod == ENC_MOD) {
            System.out.println("Car: " + car / N);
            System.out.println("Ones: " + ones / N);
            System.out.println("Zeros: " + zeros / N);
        }

    }

    private void countBitsInString(String data, String enc) {
        for (int i = 0; i < data.length(); i++) {
            int x = Integer.decode(Character.toString(data.charAt(i)));
            int y = Integer.decode(Character.toString(enc.charAt(i)));
            car += (2 * x - 1) * (2 * y - 1);
            if (y == 0) zeros++;
            else ones++;
        }
    }

    private void countCar(byte[] data, byte[] enc_data) {
        for (int i = 0; i < data.length; i++) {
            String binStrData = addZeros(Integer.toBinaryString(((int) data[i]) & 0xff));
            String binStrEnc = addZeros(Integer.toBinaryString(((int) enc_data[i]) & 0xff));
            countBitsInString(binStrData, binStrEnc);
        }
    }

    private String addZeros(String binStr) {
        StringBuffer newBinString = new StringBuffer();
        for (int i = 0; i < (8 - binStr.length()); i++) {
            newBinString.append("0");
        }
        newBinString.append(binStr);
        return newBinString.toString();
    }

    private long keyToLong(byte[] key) {
        return (key[0] << 56) ^
                (key[1] << 48) ^
                (key[2] << 40) ^
                (key[3] << 32) ^
                (key[4] << 24) ^
                (key[5] << 16) ^
                (key[6] << 8) ^
                (key[7]);
    }

    public byte[] encryptionBlock(byte[] data) {
        for (int i = 0; i < ROUNDS; i++) {
            data = firstImposition(data, expendetKeys[i * 2]);
            data = nonlinearTransform(data);
            data = secondImposition(data, expendetKeys[i * 2 + 1]);
            data = triplePHT(data);
        }

        data = firstImposition(data, expendetKeys[ROUNDS * 2]);
        return data;
    }

    public byte[] decryptionBlock(byte[] data) {
        data = firstImpositionInv(data, expendetKeys[ROUNDS * 2]);
        for (int i = ROUNDS - 1; i >= 0; i--) {
            data = tripleIPHT(data);
            data = secondImpositionInv(data, expendetKeys[i * 2 + 1]);
            data = nonlinearTransformInv(data);
            data = firstImpositionInv(data, expendetKeys[i * 2]);
        }
        return data;
    }

    private byte[] nonlinearTransform(byte[] data) {
        return nonlinearTransform(data, ENC_MOD);
    }

    private byte[] nonlinearTransformInv(byte[] data) {
        return nonlinearTransform(data, DEC_MOD);
    }

    private byte[] nonlinearTransform(byte[] data, int mod) {
        data[0] = (mod == ENC_MOD) ? functionE(data[0]) : functionL(data[0]);
        data[1] = (mod == ENC_MOD) ? functionL(data[1]) : functionE(data[1]);
        data[2] = (mod == ENC_MOD) ? functionL(data[2]) : functionE(data[2]);
        data[3] = (mod == ENC_MOD) ? functionE(data[3]) : functionL(data[3]);
        data[4] = (mod == ENC_MOD) ? functionE(data[4]) : functionL(data[4]);
        data[5] = (mod == ENC_MOD) ? functionL(data[5]) : functionE(data[5]);
        data[6] = (mod == ENC_MOD) ? functionL(data[6]) : functionE(data[6]);
        data[7] = (mod == ENC_MOD) ? functionE(data[7]) : functionL(data[7]);
        return data;
    }

    private byte sum(byte a, byte b, int mod) {
        byte result;
        int tmp1 = ((int) a) & 0xff;
        int tmp2 = ((int) b) & 0xff;
        if (mod == ENC_MOD) {
            result = (byte) ((tmp1 + tmp2) % 256);
        } else {
            result = (byte) ((256 + tmp1 - tmp2) % 256);
        }
        return result;
    }

    private byte[] firstImposition(byte[] data, byte[] keys) {
        return firstImposition(data, keys, ENC_MOD);
    }

    private byte[] firstImpositionInv(byte[] data, byte[] keys) {
        return firstImposition(data, keys, DEC_MOD);
    }

    private byte[] firstImposition(byte[] data, byte[] keys, int mod) {
        byte[] result = new byte[8];
        result[0] = (byte) (data[0] ^ keys[0]);
        result[1] = sum(data[1], keys[1], mod);
        result[2] = sum(data[2], keys[2], mod);
        result[3] = (byte) (data[3] ^ keys[3]);
        result[4] = (byte) (data[4] ^ keys[4]);
        result[5] = sum(data[5], keys[5], mod);
        result[6] = sum(data[6], keys[6], mod);
        result[7] = (byte) (data[7] ^ keys[7]);
        return result;
    }

    private byte[] secondImposition(byte[] data, byte[] keys) {
        return secondImposition(data, keys, ENC_MOD);
    }

    private byte[] secondImpositionInv(byte[] data, byte[] keys) {
        return secondImposition(data, keys, DEC_MOD);
    }

    private byte[] secondImposition(byte[] data, byte[] keys, int mod) {
        byte[] result = new byte[8];
        result[0] = sum(data[0], keys[0], mod);
        result[1] = (byte) (data[1] ^ keys[1]);
        result[2] = (byte) (data[2] ^ keys[2]);
        result[3] = sum(data[3], keys[3], mod);
        result[4] = sum(data[4], keys[4], mod);
        result[5] = (byte) (data[5] ^ keys[5]);
        result[6] = (byte) (data[6] ^ keys[6]);
        result[7] = sum(data[7], keys[7], mod);
        return result;
    }

    private byte[] PHT(byte x1, byte x2) {
        int tmp1, tmp2;
        byte[] result2Byte = new byte[2];
        tmp1 = ((int) x1) & 0xff;
        tmp2 = ((int) x2) & 0xff;
        result2Byte[0] = (byte) ((2 * tmp1 + tmp2) % 256);
        result2Byte[1] = (byte) ((tmp1 + tmp2) % 256);
        return result2Byte;
    }

    private byte[] IPHT(byte x1, byte x2) {
        int tmp1, tmp2;
        byte[] result2Byte = new byte[2];
        tmp1 = ((int) x1) & 0xff;
        tmp2 = ((int) x2) & 0xff;
        result2Byte[0] = (byte) ((256 + tmp1 - tmp2) % 256);
        result2Byte[1] = (byte) ((256 + (-1) * tmp1 + 2 * tmp2) % 256);
        return result2Byte;
    }

    private byte[] triplePHT(byte[] data) {
        return triplePHT(data, ENC_MOD);
    }

    private byte[] tripleIPHT(byte[] data) {
        return triplePHT(data, DEC_MOD);
    }

    private byte[] triplePHT(byte[] data, int mod) {
        byte[] res00 = (mod == ENC_MOD) ? PHT(data[0], data[1]) : IPHT(data[0], data[1]);
        byte[] res01 = (mod == ENC_MOD) ? PHT(data[2], data[3]) : IPHT(data[2], data[3]);
        byte[] res02 = (mod == ENC_MOD) ? PHT(data[4], data[5]) : IPHT(data[4], data[5]);
        byte[] res03 = (mod == ENC_MOD) ? PHT(data[6], data[7]) : IPHT(data[6], data[7]);

        byte[] res10 = (mod == ENC_MOD) ? PHT(res00[0], res01[0]) : IPHT(res00[0], res02[0]);
        byte[] res11 = (mod == ENC_MOD) ? PHT(res02[0], res03[0]) : IPHT(res00[1], res02[1]);
        byte[] res12 = (mod == ENC_MOD) ? PHT(res00[1], res01[1]) : IPHT(res01[0], res03[0]);
        byte[] res13 = (mod == ENC_MOD) ? PHT(res02[1], res03[1]) : IPHT(res01[1], res03[1]);

        byte[] res0 = (mod == ENC_MOD) ? PHT(res10[0], res11[0]) : IPHT(res10[0], res12[0]);
        byte[] res1 = (mod == ENC_MOD) ? PHT(res12[0], res13[0]) : IPHT(res10[1], res12[1]);
        byte[] res2 = (mod == ENC_MOD) ? PHT(res10[1], res11[1]) : IPHT(res11[0], res13[0]);
        byte[] res3 = (mod == ENC_MOD) ? PHT(res12[1], res13[1]) : IPHT(res11[1], res13[1]);

        data[0] = res0[0];
        data[1] = res0[1];
        data[2] = res1[0];
        data[3] = res1[1];
        data[4] = res2[0];
        data[5] = res2[1];
        data[6] = res3[0];
        data[7] = res3[1];
        return data;
    }

    public byte functionE(byte x) { // x = 128 => y = 256 = 0
        int x1 = ((int) x) & 0xff;
        int y = 1;
        if (x1 == 128) {
            y = 0;
        } else {
            for (int i = 0; i < x1; i++) {
                y = ((y * 45) % 257);
            }
        }
        return (byte) y;
    }

    public byte functionL(byte x) {
        int x1 = ((int) x) & 0xff;
        int y = 1;
        int tmp = 1;
        if (x1 == 0) {
            y = 128;
        } else if (x1 == 1) {
            y = 0;
        } else {
            for (y = 1; y < 256; y++) {
                tmp = ((tmp * 45) % 257);
                if (tmp == x1)
                    break;
            }
        }
        return (byte) y;
    }

    public void generation_key(long key) {
        long previos = 0;
        int id = 0;
        for (int i = 0; i < ROUNDS * 2 + 1; i++) {
            if (i == 0) {
                expendetKeys[id] = getBytes(key);
                previos = key;
                id++;
                continue;
            }
            previos = Long.rotateLeft(previos, 3);
            expendetKeys[id] = getBytesAndSum(previos, TABLE_B[id - 1]);
            id++;
        }
    }

    public byte[] getBytesAndSum(long key, long b) {
        byte[] keyBytes = getBytes(key);
        byte[] bBytes = getBytes(b);
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) ((keyBytes[i] + bBytes[i]) % 256);
        }
        return result;
    }

    byte[] getBytes(long key) {
        byte[] bytes = new byte[8];
        bytes[7] = (byte) (key & 0xff);
        bytes[6] = (byte) ((key >> 8) & 0xff);
        bytes[5] = (byte) ((key >> 16) & 0xff);
        bytes[4] = (byte) ((key >> 24) & 0xff);
        bytes[3] = (byte) ((key >> 32) & 0xff);
        bytes[2] = (byte) ((key >> 40) & 0xff);
        bytes[1] = (byte) ((key >> 48) & 0xff);
        bytes[0] = (byte) ((key >> 56) & 0xff);
        return bytes;
    }

    private byte getEmptyBytes(DataInputStream dis) throws IOException {
        return dis.readByte();
    }

    private static byte[] getBytesFromFile(final DataInputStream in) throws IOException {
        byte[] dataBytes = new byte[8];
        int er = in.read(dataBytes, 0, dataBytes.length);
        if (er == -1) {
            return null;
        }
        if (er < 8) {
            for (int i = er; i < 8; i++) {
                dataBytes[i] = (byte) 0xff;
            }
        }
        return dataBytes;
    }

    private static void saveBytesToFile(byte[] bytes, final DataOutputStream out) throws IOException {
        out.write(bytes, 0, bytes.length);
    }

    private static void saveBytesToFile(byte[] bytes, DataOutputStream out, int lengthEmpty) throws IOException {
        out.write(bytes, 0, bytes.length - lengthEmpty);
    }

}
