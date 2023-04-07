package ca.ubc.cs.cs317.dnslookup;

import java.net.DatagramSocket;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.List;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object
     * with a default timeout.
     *
     * @param verbose A DNSVerbosePrinter listener object with methods to be called
     *                at key events in the query
     *                processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the
     * given question.
     *
     * @param rrs      The set of resource records to be examined
     * @param question The DNS question
     * @return true if the collection of resource records contains an answer to the
     *         given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not
     * expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME
     * records associated to the question,
     * they are retrieved recursively for new records of the same type, and the
     * returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query
     *         requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the
     *                           value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0)
            throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Answers one question. If there are valid (not expired) results in the cache,
     * returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from
     * that server
     * (using individualQueryProcess which adds all the results to the cache) and
     * repeats until either:
     * the cache contains an answer to the query, or
     * the cache contains an answer to the query that is a CNAME record rather than
     * the requested type, or
     * every "best" nameserver in the cache has already been tried.
     *
     * @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        /**
         * If there are valid (not expired) results in the cache,
         * returns these results.
         */
        List<ResourceRecord> cachedResults = cache.getCachedResults(question);
        if (cachedResults.size() > 0) {
            return cachedResults;
        }

        while (true) {
            List<ResourceRecord> bestServers = cache.getBestNameservers(question);
            List<ResourceRecord> filteredServers = cache.filterByKnownIPAddress(bestServers);

            // In case when no known ip addresses. We need to create another iterative
            // query.
            if (filteredServers.size() < 1) {
                for (ResourceRecord server : bestServers) {
                    DNSQuestion newQuestion = new DNSQuestion(server.getTextResult(), RecordType.A,
                            server.getRecordClass());
                    try {
                        DNSLookupService newLookup = new DNSLookupService(verbose);
                        Collection<ResourceRecord> responses = newLookup.iterativeQuery(newQuestion);
                        if (responses.size() > 0) {
                            for (ResourceRecord r : responses) {
                                filteredServers.add(r);
                            }
                            break;
                        }
                    } catch (Exception e) {
                        throw new DNSErrorException(e.getMessage());
                    }
                }
            }

            boolean queryWorkedFlag = false;
            for (ResourceRecord server : filteredServers) {

                Set<ResourceRecord> responses = individualQueryProcess(question, server.getInetResult());
                if (responses == null) {
                    continue;
                }

                queryWorkedFlag = true;
                Set<ResourceRecord> ans = new HashSet<>();
                for (ResourceRecord response : responses) {

                    // the cache contains an answer to the query, or
                    if (response.getHostName().equals(question.getHostName())) {
                        ans.add(response);
                    }
                    // the cache contains an answer to the query that is a CNAME record rather than
                    // the requested type, or
                    if (response.getRecordType() == RecordType.CNAME) {
                        ans.add(response);
                    }
                }
                if (ans.size() > 0) {
                    return ans;
                }

                break;
            }
            // every "best" nameserver in the cache has already been tried.
            if (!queryWorkedFlag) {
                return null;
            }
        }
    }

    /**
     * Handles the process of sending an individual DNS query with a single
     * question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do
     * not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the
     * request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times,
     * after which the function should return
     * without changing any values. If a response is received, all of its records
     * are added to the cache.
     * <p>
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query
     * message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of
     *         all resource records
     *         received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {

        int attemptsLeft = MAX_QUERY_ATTEMPTS;

        DNSMessage message = buildQuery(question);
        byte[] buf = message.getUsed();
        DatagramPacket p = new DatagramPacket(buf, buf.length, server, DEFAULT_DNS_PORT);

        while (attemptsLeft > 0) {
            try {

                verbose.printQueryToSend(question, server, message.getID());
                socket.send(p);

                byte[] response = new byte[MAX_DNS_MESSAGE_LENGTH];
                DatagramPacket respPacket = new DatagramPacket(response, response.length);

                DNSMessage respMessage = null;

                while (respMessage == null ||
                        (respMessage.getID() != message.getID()) ||
                        (!respMessage.getQuestion().equals(question)) ||
                        (respMessage.getQR() != true)) {
                    socket.receive(respPacket);
                    respMessage = new DNSMessage(respPacket.getData(), MAX_DNS_MESSAGE_LENGTH);
                }

                // creating new DNSMessage to reset buffer position since we called
                // getQuestion().
                respMessage = new DNSMessage(respPacket.getData(), MAX_DNS_MESSAGE_LENGTH);

                // If r code does not equal 0
                if (respMessage.getRcode() != 0) {
                    throw new DNSErrorException("non zero r code found");
                }

                Set<ResourceRecord> set = processResponse(respMessage);
                for (ResourceRecord r : set) {
                    cache.addResult(r);
                }
                return set;

            } catch (SocketTimeoutException e) {
                System.out.println("Error: Socket timeout");
            } catch (IOException e) {
                System.out.println("Error: IOException thrown");
            }

            attemptsLeft--;
        }

        return null;
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding
     * part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query
     * with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`)
     * must be equivalent
     * to the size of the query data.
     *
     * @param question Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        short id = (short) random.nextInt(Short.MAX_VALUE + 1);
        DNSMessage message = new DNSMessage(id);
        message.addQuestion(question);
        return message;
    }

    /**
     * Parses and processes a response received by a nameserver.
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing
     * sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the
     * priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data
     * represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException {

        // System.out.println(message.toString());

        verbose.printResponseHeaderInfo(message.getID(), message.getAA(), message.getRcode());

        if (message.getRcode() != 0) {
            throw new DNSErrorException("non zero r code found");
        }

        // To get buffer position to be in correct position.
        int qdCount = message.getQDCount();
        for (int i = 0; i < qdCount; i++) {
            message.getQuestion();
        }

        Set<ResourceRecord> rrs = new HashSet<ResourceRecord>();
        int nrrs = message.getANCount();
        verbose.printAnswersHeader(nrrs);
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = message.getRR();
            rrs.add(rr);
            cache.addResult(rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
        }

        nrrs = message.getNSCount();
        verbose.printNameserversHeader(nrrs);
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = message.getRR();
            rrs.add(rr);
            cache.addResult(rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
        }

        nrrs = message.getARCount();
        verbose.printAdditionalInfoHeader(nrrs);
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = message.getRR();
            rrs.add(rr);
            cache.addResult(rr);
            verbose.printIndividualResourceRecord(rr, rr.getRecordType().getCode(), rr.getRecordClass().getCode());
        }

        return rrs;
    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }
}
