

Table 1: Format for DNS Query Field
Field	Description
Transaction ID	Used by the DNS client and server to identify the transaction when it matches a request to a response.
Flags	A value of R indicates that recursion was requested; otherwise, the field is empty.
When recursion is requested and enabled, the DNS server makes queries on behalf of the client to resolve the domain name.

Query domain	The domain name that was requested to be resolved.
Request type	Identifies the type of resource information that was requested, as defined by the Internet Assigned Numbers Authority (IANA).
Some of the most common requests types include IPv4 host address (A), IPv6 address (AAAA), canonical domain name for the alias (CNAME), the authoritative name server for the domain (NS), and name of the mail exchange server (MX).


## DNS Query
DNS Query uses this format
<transaction ID>,<flags>,<query domain>,<request type>

```
5173, R, google.com, A
```
(37798, 1, 32, 1, 0, 0, 1)


# DNS Response
DNS Response uses this format
<transaction id>,<flags>,<query domain>,<response code>,<num answers>,<num authority>,<num additional>,<answers>


Table 2: Format for DNS Response Field
Field | Description
Transaction ID	Used by the DNS client and server to identify the transaction when it matches a request to a response.
Flags	Might be empty, or some combination of A,R, and T where
A means that the response is authoritative.
R means that recursion is available.
T means that the response was truncated.
Query domain	The domain name that was requested to be resolved.
Response code	A response code of 0 means that no errors were encountered. All other response code values indicate some type of error. For example, the query might be formatted improperly or the domain name might not exist.
Num answers	The number of regular answer records that were returned by the query.
Num authority	The number of authority answer records that were returned by the query.
Num additional	The number of extra answer records that were returned by the query.
Answers	The list of answer responses that were returned by the query.
Each answer is separated by the "|" symbol. Authority and additional answers have the same format as regular answers, and are denoted as authority and additional answers based on their location in the answers list.