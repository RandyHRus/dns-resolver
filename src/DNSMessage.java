package ca.ubc.cs.cs317.dnslookup;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.IntStream;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;

    // The offset into the message where the header ends and the data begins.
    public final static int DataOffset = 12;

    // Opcode for a standard query
    public final static int QUERY = 0;

    private final ByteBuffer buffer;

    // name to pointer offset
    private HashMap<String, Integer> offsetMap = new HashMap<String, Integer>();

    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        buffer.putShort(0, id);
        buffer.position(DataOffset);
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd  The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        buffer.position(DataOffset);
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a
     * DNSMessage
     */
    public int getID() {
        short id = buffer.getShort(0);
        return (id & 0xFFFF);
    }

    public void setID(int id) {
        buffer.putShort(0, (short) id);
    }

    public boolean getQR() {
        byte b = buffer.get(2);
        return ((b & 0b10000000) >> 7) == 1;
    }

    public void setQR(boolean qr) {
        byte b = buffer.get(2);
        b = qr ? (byte) (b | 0b10000000) : (byte) (b & 0b01111111);
        buffer.put(2, b);
    }

    public boolean getAA() {
        byte b = buffer.get(2);
        return ((b & 0b00000100) >> 2) == 1;
    }

    public void setAA(boolean aa) {
        byte b = buffer.get(2);
        b = aa ? (byte) (b | 0b00000100) : (byte) (b & 0b11111011);
        buffer.put(2, b);
    }

    public int getOpcode() {
        int b = buffer.get(2);
        b = 0b00001111 & (b >> 3);
        return b;
    }

    public void setOpcode(int opcode) {
        byte b = buffer.get(2);
        b = (byte) (0b10000111 & b);
        opcode = opcode << 3;
        b = (byte) (b | (opcode & 0b01111000));
        buffer.put(2, b);
    }

    public boolean getTC() {
        byte b = buffer.get(2);
        return ((b & 0b00000010) >> 1) == 1;
    }

    public void setTC(boolean tc) {
        byte b = buffer.get(2);
        b = tc ? (byte) (b | 0b00000010) : (byte) (b & 0b11111101);
        buffer.put(2, b);
    }

    public boolean getRD() {
        byte b = buffer.get(2);
        return (b & 0b00000001) == 1;
    }

    public void setRD(boolean rd) {
        byte b = buffer.get(2);
        b = rd ? (byte) (b | 0b00000001) : (byte) (b & 0b11111110);
        buffer.put(2, b);
    }

    public boolean getRA() {
        byte b = buffer.get(3);
        return ((b & 0b10000000) >> 7) == 1;
    }

    public void setRA(boolean ra) {
        byte b = buffer.get(2);
        b = ra ? (byte) (b | 0b10000000) : (byte) (b & 0b01111111);
        buffer.put(3, b);
    }

    public int getRcode() {
        byte b = buffer.get(3);
        return (b & 0b00001111);
    }

    public void setRcode(int rcode) {
        byte b = buffer.get(2);
        b = (byte) ((b & 0b11110000) | rcode);
        buffer.put(3, b);
    }

    public int getQDCount() {
        return buffer.getShort(4) & 0xFFFF;
    }

    public void setQDCount(int count) {
        buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return buffer.getShort(6) & 0xFFFF;
    }

    public void setANCount(int count) {
        buffer.putShort(6, (short) count);
    }

    public int getNSCount() {
        return buffer.getShort(8) & 0xFFFF;
    }

    public void setNSCount(int count) {
        buffer.putShort(8, (short) count);
    }

    public int getARCount() {
        return buffer.getShort(10) & 0xFFFF;
    }

    public void setARCount(int count) {
        buffer.putShort(10, (short) count);
    }

    /**
     * Return the name at the current position() of the buffer.
     *
     * The encoding of names in DNS messages is a bit tricky.
     * You should read section 4.1.4 of RFC 1035 very, very carefully. Then you
     * should draw a picture of
     * how some domain names might be encoded. Once you have the data structure
     * firmly in your mind, then
     * design the code to read names.
     *
     * @return The decoded name
     */
    public String getName() {
        StringBuilder sb = new StringBuilder();
        byte currentByte;
        int comeBackOffset = -1;
        while ((currentByte = buffer.get()) != 0) {
            // case that it is a pointer
            if ((0b11000000 & currentByte) == 0b11000000) {
                byte[] offsetArray = new byte[] { (byte) (0b00111111 & currentByte), buffer.get() };
                int offset = ByteBuffer.wrap(offsetArray).getShort() & 0xFFFF;
                /**
                 * Once we are done reading the data at the destination
                 * of the pointer, we need to reset position back.
                 */
                if (comeBackOffset == -1) {
                    comeBackOffset = buffer.position();
                }
                buffer.position(offset);
            }
            // case that it is not a pointer
            else if ((0b11000000 & currentByte) == 0b00000000) {
                int length = (int) currentByte;
                for (int i = 0; i < length; i++) {
                    byte[] b = new byte[] { buffer.get() };
                    try {
                        sb.append(new String(b, "US-ASCII"));
                    } catch (UnsupportedEncodingException e) {
                        System.out.println("Failed to get name encoding");
                    }
                }
                if (buffer.get(buffer.position()) != 0) {
                    sb.append(".");
                }
            }

        }
        if (comeBackOffset != -1) {
            buffer.position(comeBackOffset);
        }

        String hostName = sb.toString();
        return hostName;
    }

    /**
     * The standard toString method that displays everything in a message.
     * 
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not
        // change
        // the position in the buffer. We remember what it was and put it back when we
        // are done.
        int end = buffer.position();
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR() ? "Response" : "Query").append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        } finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to
     * the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of
     * them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we
     *             looking at)
     * @param nrrs Number of resource records
     * @param sb   Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message. The current
     * position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        String hostName = getName();
        RecordType qType = RecordType.getByCode(buffer.getShort() & 0xFFFF);
        RecordClass qClass = RecordClass.getByCode(buffer.getShort() & 0xFFFF);
        return new DNSQuestion(hostName, qType, qClass);
    }

    /**
     * Decode and return the resource record that appears next in the message. The
     * current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {

        String hostName = getName();
        RecordType qType = RecordType.getByCode(buffer.getShort() & 0xFFFF);
        RecordClass qClass = RecordClass.getByCode(buffer.getShort() & 0xFFFF);
        int ttl = buffer.getInt();
        int rdLength = (buffer.getShort() & 0xFFFF);
        DNSQuestion q = new DNSQuestion(hostName, qType, qClass);
        ResourceRecord rr = null;

        switch (qType) {
            case A:
                try {
                    byte[] rData = new byte[rdLength];
                    buffer.get(rData, 0, rdLength);
                    InetAddress address = InetAddress.getByAddress(rData);
                    rr = new ResourceRecord(q, ttl, address);
                } catch (UnknownHostException e) {
                    System.out.println("error: Unknown host");
                }
                break;
            case NS:
                String data = getName();
                rr = new ResourceRecord(q, ttl, data);
                break;
            case CNAME:
                data = getName();
                rr = new ResourceRecord(q, ttl, data);
                break;
            case MX:
                buffer.getShort(); // read PREFERENCE
                data = getName();
                rr = new ResourceRecord(q, ttl, data);
                break;
            case AAAA:
                try {
                    byte[] rData = new byte[rdLength];
                    buffer.get(rData, 0, rdLength);
                    InetAddress address = InetAddress.getByAddress(rData);
                    rr = new ResourceRecord(q, ttl, address);
                } catch (UnknownHostException e) {
                    System.out.println("error: Unknown host");
                }
                break;
            case SOA:
                // Not part of assignment
                break;
            case OTHER:
                break;
        }

        return rr;
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May
     * be used to represent the result of
     * records that are returned by a server but are not supported by the
     * application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Helper function that returns a byte array from a hex string representation.
     * May be used to represent the result of
     * records that are returned by a server but are not supported by the
     * application (e.g., SOA records).
     *
     * @param hexString a string containing the hex value of every byte in the data.
     * @return data a byte array containing the record data.
     */
    public static byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            String s = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(s, 16);
        }
        return bytes;
    }

    /**
     * Add an encoded name to the message. It is added at the current position and
     * uses compression
     * as much as possible. Make sure you understand the compressed data format of
     * DNS names.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        addNameGetSize(name);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and
     * uses compression
     * as much as possible. Make sure you understand the compressed data format of
     * DNS names.
     *
     * @param name The name to be added
     * @return size of encoded name after compression
     */
    public int addNameGetSize(String name) {
        String[] split = name.split("\\.");
        String restOfName = name;
        int size = 0;

        for (int i = 0; i < split.length; i++) {
            restOfName = String.join(".", Arrays.copyOfRange(split, i, split.length));
            if (offsetMap.get(restOfName) != null) {
                buffer.putShort((short) (0b1100000000000000 | offsetMap.get(restOfName)));
                size += 2;
                return size;
            } else {

                offsetMap.put(restOfName, buffer.position());

                int length = split[i].length();
                byte lengthOctet = (byte) length;
                buffer.put(lengthOctet);
                size++;
                try {
                    byte[] b = split[i].getBytes("US-ASCII");
                    buffer.put(b);
                    size += b.length;
                } catch (UnsupportedEncodingException e) {
                    System.out.println("Failed to get name encoding");
                }
            }
        }
        buffer.put((byte) 0);
        size++;
        return size;
    }

    /**
     * Add an encoded question to the message at the current position.
     * 
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        addName(question.getHostName());
        addQType(question.getRecordType());
        addQClass(question.getRecordClass());
        setQDCount(getQDCount() + 1);
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * The record is added to the additional records section.
     * 
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr) {
        addResourceRecord(rr, "additional");
    }

    /**
     * Add an encoded resource record to the message at the current position.
     *
     * @param rr      The resource record to be added
     * @param section Indicates the section to which the resource record is added.
     *                It is one of "answer", "nameserver", or "additional".
     * @throws UnsupportedEncodingException
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        String name = rr.getHostName();
        RecordType qType = rr.getRecordType();
        RecordClass qClass = rr.getRecordClass();
        long ttl = rr.getRemainingTTL();

        addName(name);
        addQType(qType);
        addQClass(qClass);
        buffer.putInt((int) ttl);

        switch (qType) {
            case A:
                InetAddress ip = rr.getInetResult();
                buffer.putShort((short) 4);
                buffer.put(ip.getAddress());
                break;
            case NS:
                int lengthPos = buffer.position();
                buffer.putShort((short) 0); // Add temp length
                int size = addNameGetSize(rr.getTextResult());
                buffer.putShort(lengthPos, (short) size);
                break;
            case CNAME:
                lengthPos = buffer.position();
                buffer.putShort((short) 0); // Add temp length
                size = addNameGetSize(rr.getTextResult());
                buffer.putShort(lengthPos, (short) size);
                break;
            case MX:
                buffer.putShort((short) 0); // PREFERENCE
                lengthPos = buffer.position();
                buffer.putShort((short) 0); // Add temp length
                size = addNameGetSize(rr.getTextResult());
                buffer.putShort(lengthPos, (short) size);
                break;
            case AAAA:
                ip = rr.getInetResult();
                buffer.putShort((short) 16);
                buffer.put(ip.getAddress());
                break;
            case SOA:
                // Not part of assignment
                break;
            case OTHER:
                break;
        }

        // Increment header
        switch (section) {
            case ("answer"):
                setANCount(getANCount() + 1);
                break;
            case ("nameserver"):
                setNSCount(getNSCount() + 1);
                break;
            case ("additional"):
                setARCount(getARCount() + 1);
                break;
            default:
                break;
        }
    }

    /**
     * Add an encoded type to the message at the current position.
     * 
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        short qType = (short) recordType.getCode();
        buffer.putShort(qType);
    }

    /**
     * Add an encoded class to the message at the current position.
     * 
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        short qClass = (short) recordClass.getCode();
        buffer.putShort(qClass);
    }

    /**
     * Return a byte array that contains all the data comprising this message. The
     * length of the
     * array will be exactly the same as the current position in the buffer.
     * 
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        int arrayLength = buffer.position();
        byte[] result = new byte[arrayLength];

        buffer.position(0);
        for (int i = 0; i < arrayLength; i++) {
            result[i] = buffer.get();
        }

        return result;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[] {
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
