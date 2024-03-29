from sdc.crypto.key_store import KeyStore

TEST_DO_NOT_USE_SR_PRIVATE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAt8LZnIhuOdL/BC029GOaJkVUAqgp2PcmbFr2Qwhf/514DUUQ
9sKJ1rvwvbmmW2zE8JRtdY3ey0RXGtMn5UZHs8NReHzMxvsmHN4VuaGEnFmPwO82
1Tkvg0LpKsLkotcw793FD/fut44N2lhpTSW2Sc82uG0p9A+Kud8HCIaWaluosghk
9rbMGYDzZQk8cA91GtKJRmIOED4PorB/dexDf37qhuWNQgzyNyTti1DTDUIWyzQQ
Jp926vLbkOip6Fc2R13hOFNETe68Rrw/h3hXEFS17uPFZHsxvm9PFXX9KZMS25oh
qbNh97I94LL4o4wybl6LaE6lJEHiD6docD0B6wIDAQABAoIBADRQGyUtzbtWbtTg
jlF6fWrBt83d07P5gA2+w3aHztR1HrUgYVjuPtFLxZgtXseOKm6WwqaBkdhqByYS
0Lu7izQIuYvEc4N+Afab3rFu4tKjyIHTV9fRpM4IYVqUCwS0oDDZAH2wRlwo65aq
LqgQwVk3zUspgJUDS6nobRcnQXDbVaQ54JU0zSXrFJqZygrUR5TDuPnE7Ehbb9Ru
L1YNkxn2wVT9iOHdyaxr9co7x1z01hHCgdf3SUyGTCOCqp9rJYXtm+GPpZMRpwv7
CdsMfDxpkNKC2X/hBHz5ux9sC8kRA/JcTKGvbKbPVpedWyIYwKjJ8H1A0zuSQX9Q
rZU1a0kCgYEA3EyNsBwtllLSzA2sb1yf6qc+0mvXcPPrTt7WWG7bUI1/43Nx2rMW
XxRGdJlOdA9GnxIK2Ir75pPXj6VVL2U2CCh87td5bnVDr8DMA8nj7efpjMpAUEtU
QX/qKHtzkr3nRjLLkrL9IhQ6m9rNVtyKqWLTnBv6Uflq2UlYHh2xBi0CgYEA1Yp3
DycqKDkkGHi9wuZeyAhQDsKHyVEukS5bflVjnkbkdX7Z4efMzKdFknNk6O/YtgYh
Ti/XheojCkCVMSEJ3kndsotIsEf1kXYIvfSSBPO0J8GWma7meGbUn61Tq8Kj10LI
8k6KsXiT67+r79wOYcRclIBGNm3nR4rMMpKAj3cCgYAB6oCI+ZXD6vB+adgIF+wk
JFQ9jEaRau2u/+0pU72Ak9p65fQljM0zAoAiX3r5M3DPzV5ex8atGLgVPcDh6qVv
qLp9cU5TEZ4HF0wu9ECRPyUe3lt011LiRvSIaZp1ukUarTJsEjZ1Z2ujE2IZ0U07
b+qbPvsMX3j4btTfXi69+QKBgFZvAHgKsz6quliJbs3X719qNfVzegDbskyjhfch
2vuy2EBSwyB0ceoYfsmjmaHLi11KJ+r85HDY76vzri+/nr3yCiF9zUNFLTnem/U/
bGdCuZYp/qpgJ/tuK/wh7S8lzqmP58RkVDE3jDAtWgvxd4TNNWgKb+ESJT5JCRQj
RpRLAoGALFlPzTd/ifWCcV0Pn5U/ESzX1az2kfll30VxjfGVFsRJ4ZvezxgI+vwo
OZrki4MBTK/6GFkHLFkF6w2Le+Y5Nos9O2UUZs45lwLEYbQ4yKcx2KlWGLZOypB8
i7/6TB95Ej2i5KgaSlcJjOyOx7g20TwDD1THtLXgY54d0Yr9T/U=
-----END RSA PRIVATE KEY-----
"""

TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvZzMraB96Wd1zfHS3vW3
z//Nkqz+9HfwViNje2Y5L6m3K/7raA0kUsWD1f6X7/LIJfkCEctCEj9q19+cX30h
0pi6IOu92MlIwdH/L6CTuzYnG4PACKT8FZonLw0NYBqh8p4vWS8xtNHNjTWua/FF
TlxdtYnEb9HbUZkg7dXAtnikozlE/ZZSponq7K00h3Uh9goxQIavcK1QI8pw5V+T
8V8Ue7k98W8LpbYQWm7FPOZayu1EoJWUZefdOlYAdeVbDS4tjrVF+3za+VX3q73z
JEfyLEM0zKrkQQ796gfYpkzDYwJvkiW7fb2Yh1teNHpFR5tozzMwUxkREl/TQ4U1
kwIDAQAB
-----END PUBLIC KEY-----"""

VALID_SIGNED_JWT = "eyJraWQiOiI3MDllYjQyY2ZlZTU1NzAwNThjZTA3MTFmNzMwYmZiYjdkNGM4YWRlIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJqd3" \
                   "QifQ.eyJ1c2VyIjoiamltbXkiLCJpYXQiOjE0OTgxMzc1MTkuMTM1NDc5LCJleHAiOjEuMDAwMDAwMDAwMDAxNDk4MmUrMjF9.tXGcIZf" \
                   "bTIgxrd7ILj_XqcoiRLtmgjnJ0WORPBJ4M9Kd3zKTBkoIM6pN5XWdqsfvdby53mxQzi3_DZS4Ab4XvF29Wce49GVv7k69ZZJ-5g2NX9iJ" \
                   "y4_Be8uTZNKSwMpfrnkRrsbaWAGrXe9NKC3WC_Iq4UuE3KM7ltvOae4be-2863DP7_QEUtaAtXSwUkjPcgkvMPns-SurtFNXgFFVToNnw" \
                   "IuJ9UWsY8JlX1UB56wfqu68hbl88lenIf9Ym0r5hq0DlOZYNtjVizVDFciRx_52d4oeKMSzwJ1jB5aZ7YKRNHTo38Kltb5FkHRcIkV1Ae" \
                   "68-5dZeE9Yu_JHPMi_hw"

VALID_JWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJlMTkwOTEwNzJmOTIwY2JmM2NhOWY0MzZjZWJhMzA5ZTdkODE0Y" \
            "TYyIn0.SZG8UMNXYGnjppgGf1ok_O93Z_5qzKEZmn35pbStiDzAYdrUgg4Aa04B6ivDzPaZu-ROYTRw8UsroK8OEkySMDuHw0s63Z2AOZ" \
            "K6qviFfobxQFGnndEro9HrDTYMM9dpOt-_uFO0Ezuxyo7dkvRnAnRv4wy7Tqwu0CXtHcv5wzeUlGzh2OGR9nNK_6_2eRF8Lu3wuV5INa2" \
            "VSppU3xeQZQsuc1e-XoHi_fNzr8Lckmv9Cl5Z19BeC5DPhQb1IK8rRKyxIU8h65yoDEGfsD0Mf62wvdTFOldQ_gwCjSw3Piez_V2g9FUv" \
            "entQKVH28_pqBAZrUBj-Ma9FfNuWrJJo-w.1fsxK2D0kHa5RXW8.xO6V9QtVbKkBd9n75Bs0MugZ85oXVSqiKqwXEOc-_BqM0_1LtBbx9" \
            "Q6hsvwZ84f3vakIy4AiFPKhEY_ofbokEqMnFPEg0s2U7oux-vZcNU5Db4F_TO_3bMEetyUoPiOJeJztTI-an2A4oQjSB0rniXaaAI3buD" \
            "D43CvfS-SBuWHDQ6CD7ntca2hWzcO8YpnZsSKJad9FquHW_VpOj1nXnNh73q_qHXuB6USF5l3IPndep0KRwj8fUQTF9l358uWChJ2VtLK" \
            "_gvw_H7PSMdgHzpj1o4Nv22boVhnhtG7ns-tP53Lec01C_qAbRGnQ30eHZsbdpnAeIrOl9_2p_rjOO6ua5K5tnD2fQp1_8MXf1Ezbr1pc" \
            "p_gfk4eDJCxKblpn3Q22YtsF3qCtPS3Xz7izPz0UCK7EJy6yRU3UcLQ3YyTfCVRK1RJpgpyltCsABS6IRuw0OXmXHNy-GKB0w19hVeXU-" \
            "gcY7FH9ldespOEnruTaOSWB7tcMoKyAgH3nZqZbx0NMJiAcXFJowWSzcLtrfUOZ5nU5hnXretpD0VD45mnze4TVfvt1lCY-EGMoWM1HmW" \
            "YIdIo013famiRIrs2peofThYZ3aGq-WatXHuBT1SJO_CV8gT8ifOLJX0UqH1wwVKjgfxelwtNOFNDe7Hq0iu2p-skwsI8P_N87RiByCue" \
            "Pw2HLVu4kzag21xtXnDz9rcPgeWiAS4ji9g.IM-8SjLJH-NFBLkg5EkAmg"

TOO_FEW_TOKENS_JWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00iLCJraWQiOiJlMTkwOTEwNzJmOTIwY2JmM2NhOWY0MzZjZWJhMzA5ZTdkODE0Y" \
                     "TYyIn0.SZG8UMNXYGnjppgGf1ok_O93Z_5qzKEZmn35pbStiDzAYdrUgg4Aa04B6ivDzPaZu-ROYTRw8UsroK8OEkySMDuHw0s63Z2AOZ" \
                     "K6qviFfobxQFGnndEro9HrDTYMM9dpOt-_uFO0Ezuxyo7dkvRnAnRv4wy7Tqwu0CXtHcv5wzeUlGzh2OGR9nNK_6_2eRF8Lu3wuV5INa2" \
                     "VSppU3xeQZQsuc1e-XoHi_fNzr8Lckmv9Cl5Z19BeC5DPhQb1IK8rRKyxIU8h65yoDEGfsD0Mf62wvdTFOldQ_gwCjSw3Piez_V2g9FUv" \
                     "entQKVH28_pqBAZrUBj-Ma9FfNuWrJJo-w.1fsxK2D0kHa5RXW8.xO6V9QtVbKkBd9n75Bs0MugZ85oXVSqiKqwXEOc-_BqM0_1LtBbx9" \
                     "Q6hsvwZ84f3vakIy4AiFPKhEY_ofbokEqMnFPEg0s2U7oux-vZcNU5Db4F_TO_3bMEetyUoPiOJeJztTI-an2A4oQjSB0rniXaaAI3buD" \
                     "D43CvfS-SBuWHDQ6CD7ntca2hWzcO8YpnZsSKJad9FquHW_VpOj1nXnNh73q_qHXuB6USF5l3IPndep0KRwj8fUQTF9l358uWChJ2VtLK" \
                     "_gvw_H7PSMdgHzpj1o4Nv22boVhnhtG7ns-tP53Lec01C_qAbRGnQ30eHZsbdpnAeIrOl9_2p_rjOO6ua5K5tnD2fQp1_8MXf1Ezbr1pc" \
                     "p_gfk4eDJCxKblpn3Q22YtsF3qCtPS3Xz7izPz0UCK7EJy6yRU3UcLQ3YyTfCVRK1RJpgpyltCsABS6IRuw0OXmXHNy-GKB0w19hVeXU-" \
                     "gcY7FH9ldespOEnruTaOSWB7tcMoKyAgH3nZqZbx0NMJiAcXFJowWSzcLtrfUOZ5nU5hnXretpD0VD45mnze4TVfvt1lCY-EGMoWM1HmW" \
                     "YIdIo013famiRIrs2peofThYZ3aGq-WatXHuBT1SJO_CV8gT8ifOLJX0UqH1wwVKjgfxelwtNOFNDe7Hq0iu2p-skwsI8P_N87RiByCue" \
                     "Pw2HLVu4kzag21xtXnDz9rcPgeWiAS4ji9g"

TEST_DO_NOT_USE_UPSTREAM_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvZzMraB96Wd1zfHS3vW3z//Nkqz+9HfwViNje2Y5L6m3K/7r
aA0kUsWD1f6X7/LIJfkCEctCEj9q19+cX30h0pi6IOu92MlIwdH/L6CTuzYnG4PA
CKT8FZonLw0NYBqh8p4vWS8xtNHNjTWua/FFTlxdtYnEb9HbUZkg7dXAtnikozlE
/ZZSponq7K00h3Uh9goxQIavcK1QI8pw5V+T8V8Ue7k98W8LpbYQWm7FPOZayu1E
oJWUZefdOlYAdeVbDS4tjrVF+3za+VX3q73zJEfyLEM0zKrkQQ796gfYpkzDYwJv
kiW7fb2Yh1teNHpFR5tozzMwUxkREl/TQ4U1kwIDAQABAoIBAHXiS1pTIpT/Dr24
b/rQV7RIfF2JkoUZIGHdZJcuqbUZVdlThrXNHd0cEWf0/i9fCNKa6o93iB9iMCIA
Uu8HFAUjkOyww/pIwiRGU9ofglltRIkVs0lskZE4os3c1oj+Zds6P4O6FLQvkBUP
394aRZV/VX9tJKTEmw8zHcbgEw0eBpiY/EMELcSmZYk7lhB80Y+idTrZcHoV4AZo
DhQwyF0R63mMphuOV4PwaCdCYZKgd/tr2uUHglLpYbQag3iEzoDfxdFcxnRkBdOi
a/wcNo0JRlMsxXmtJ+HrZar+6ObUx5SgLGz7dQnKvP/ZgenTk0yyohwikh2b2KOS
M3M2oUkCgYEA9+olFPDZxtM1fwmlXcymBtokbiki/BJQGJ1/5RMqvdsSeq8icl/i
Qk5AoNbWEcsAxeBftb1IfnxJsRthRyp0NX5HOSsBFiIfdSF225nmBpktwPjJmvZZ
G2MQCVqw9Y40Cia0LZnRo8417ahSfVf8/IoggnAwkswJ3fkktt/FlW8CgYEAw8vi
7hWxehiUaZO4RO7GuV47q4wPZ/nQvcimyjJuXBkC/gQay+TcA7CdXQTgxI2scMIk
UPas36mle1vbAp+GfWcNxDxhmSnQvUke4/wHF6sNZ3BwKoTRqJqFcFUHm+2uo6A4
HCBtXM83Z1nDYkHUrfng99U+zgGDz2XKPko9OB0CgYAtVVOSkLhB8z1FDa5/iHyT
pDAlNMCA95hN5/8LFIYsUXL/nCbgY0gsd8K5po9ekZCCnpTh1sr61h9jk24mZUz6
uyyq94IrWfIGqSfi4DF/42LKdrPm8kU5DNRR4ZOaU3aQpKMt84KyQXL7ElyDLyPD
yj5Hm9xF+6mSPYzJJAItYQKBgHzUZXbzf7ZfK2fwVSAlt68BJDvnzP62Z95Hqgbp
hjDThXPbvBXYcGkt1fYzIPZPeOxe6nZv/qGOcEGou4X9nOogpMdC09qprTqw/q/N
w9vUI3SaW/jPuzeqZH7Mx1Ajhh8uC/fquK7eMe2Dbi0b2XOeB08atrLyhk3ZEMsL
2+IFAoGAUbmo0idyszcarBPPsiEFQY2y1yzHMajs8OkjUzOVLzdiMkr36LF4ojgw
UCM9sT0g1i+eTfTcuOEr3dAxcXld8Ffs6INSIplvRMWH1m7wgXMRpPCy74OuxlDQ
xwPp/1IVvrMqVgnyS9ezAeE0p9u8zUdZdwHz1UAggwbtHR6IbIA=
-----END RSA PRIVATE KEY-----
"""

TEST_DO_NOT_USE_SR_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8LZnIhuOdL/BC029GOa
JkVUAqgp2PcmbFr2Qwhf/514DUUQ9sKJ1rvwvbmmW2zE8JRtdY3ey0RXGtMn5UZH
s8NReHzMxvsmHN4VuaGEnFmPwO821Tkvg0LpKsLkotcw793FD/fut44N2lhpTSW2
Sc82uG0p9A+Kud8HCIaWaluosghk9rbMGYDzZQk8cA91GtKJRmIOED4PorB/dexD
f37qhuWNQgzyNyTti1DTDUIWyzQQJp926vLbkOip6Fc2R13hOFNETe68Rrw/h3hX
EFS17uPFZHsxvm9PFXX9KZMS25ohqbNh97I94LL4o4wybl6LaE6lJEHiD6docD0B
6wIDAQAB
-----END PUBLIC KEY-----
"""

TEST_DO_NOT_USE_EQ_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwgSIPwv72JfGe87Jf+gI5HSzZfWRJEzAynv6g94rr78spbag
+4Q/63Zl1EBfKnOqZBBmDbBMoSFpGRWchW8YkYvo3jJx74ns0LkxDvDEXfKHAu64
w5AwvGjodSy2FP1vjz7U5rpAmhtB4hv5TVlMhCdLlXm5Xh66mpmRtGfVHrSfrqLs
RecGg2IOGstGRBcykBL2cewWEaW0ORm+L1zkUIUzrtdcGtX5iFrTd/Q5AUYXS8hf
4lIOkZc24nzj/ZGA+u8/fEKyHk9rNNHndRgQlivlorbF2L8+LF01V7GhkrwXV+gB
itIo7c2bGJjVVKIlJNK8aYqm2vnyli/J8ClSvQIDAQABAoIBADXYJCe7H63AkWkS
voEs2Cru6ErHl/xHAMoxFhk6s00W9UEYKh0jWsnyFdiN9NtHNmaG1ou9/cZKC2zW
vpWZe2wJNBtWTKB52qsieib3Usfv4uBBeC1t+tiPFNRQEEhK/Yb3nQZbckpSfjpO
ISYCPmX+sc9N9M/WH1uAextiJZdbdanuGC3TETj0qugb+3UGX/z4hVZKEPRVGxlf
oVULcbM9auKv9OGJJcNGlIva1nZeapb+jhlgmfwJVCDr7vNtKC1D6sziU+HGj0dP
3A4+FaGU9akfQPDUkYt7tfXNiGcYa5CEYyzBwZ7RQ1RnZoUjA0m0Nhb3VrQoQblA
5a7BqNECgYEA4+V/R9HPz9RKWsaWTtqB8PpO/XuxmGta8TME2YVdtSMTrlL/riza
OlXVTFK+dlyT+9WpDgmQStK8DBAh1nmu4EqdDrYvOtYUd6SHMNC40szvS3jMbfNp
AXEmoqToabGTASqWv55sbQMA0OZE0QIEHoIYNiUVDDUqIe0I85Tiwi8CgYEA2fGC
pgfyhNRH5V6U9yxNShh9K3r+ioI7AW0vtezCOmZgQ1D+I5PRMXttJvL/kPgQn3eR
7tB/u5Kra/yGLlj7hKxShwPvT10G+IxOfpfX1u3aJIWd25UWPvuMIUmCstTufw1l
P6fA6HFuV9N6p4gGdUG6sj/91CNSLm/M8Jj9mtMCgYEAxwRT8tQ3Nredd0iVWqdX
cqok8RhkL0cRVDHJumvNObI4LbQttF1W9jqe2tgnnBWc5f/gcnHHoJAHyEEOS85X
+WcvYPmYpTjvBsyXgvnDbdOp5a7IV/yJZsj5hG+exy5bwlj+7Lfc2BYXUFbHIf8w
ubPCkQYxK0gCUz484vrSS+ECgYBxAdeau7g2w9PbzSU03RXee8A7kXT24PwziygY
DwHPQlJb1V1RmU35eGRqs8lspBQKe/eBez8gRbb5MWFqGt2gN7I7LAEkh7obmrUA
0z8pxP89vMLTnwR/9/L7N6C7lclsu8dqMFPIszhh9dg9kjy3BDQIRUIag44TYglE
IDAv3QKBgQC6ZH412yYMqGz3VKpCnE8NfoSMpUhFl1tpS12NNohVarJPABspn6rX
mYWGeHCFOvLLeeW9SI3T8R+uar4cCyRVtCCi1n05D/Gmy10Enf8QyZFx3mMwuWLq
5QIaYe1+U/9+2rdrEt7XL3Q8gbIJ98sebY+/on1AYEKEU2YpQ+v2ng==
-----END RSA PRIVATE KEY-----
"""

TEST_DO_NOT_USE_EQ_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgSIPwv72JfGe87Jf+gI
5HSzZfWRJEzAynv6g94rr78spbag+4Q/63Zl1EBfKnOqZBBmDbBMoSFpGRWchW8Y
kYvo3jJx74ns0LkxDvDEXfKHAu64w5AwvGjodSy2FP1vjz7U5rpAmhtB4hv5TVlM
hCdLlXm5Xh66mpmRtGfVHrSfrqLsRecGg2IOGstGRBcykBL2cewWEaW0ORm+L1zk
UIUzrtdcGtX5iFrTd/Q5AUYXS8hf4lIOkZc24nzj/ZGA+u8/fEKyHk9rNNHndRgQ
livlorbF2L8+LF01V7GhkrwXV+gBitIo7c2bGJjVVKIlJNK8aYqm2vnyli/J8ClS
vQIDAQAB
-----END PUBLIC KEY-----
"""


# jwt.io public key signed
TEST_DO_NOT_USE_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3Wojg
GHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlv
dbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GU
nKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
-----END PUBLIC KEY-----"""


def get_mock_key_store(key_purpose):
    return KeyStore(
        {
            "keys": {
                "e19091072f920cbf3ca9f436ceba309e7d814a62": {
                    "purpose": key_purpose,
                    "type": "private",
                    "value": TEST_DO_NOT_USE_SR_PRIVATE_PEM,
                },
                "EQ_USER_AUTHENTICATION_SR_PRIVATE_KEY": {
                    "purpose": key_purpose,
                    "type": "private",
                    "value": TEST_DO_NOT_USE_SR_PRIVATE_PEM,
                    "service": "some-service",
                },
                "EDCRRM": {
                    "purpose": key_purpose,
                    "type": "public",
                    "value": TEST_DO_NOT_USE_PUBLIC_KEY,
                    "service": "some-service",
                },
                "709eb42cfee5570058ce0711f730bfbb7d4c8ade": {
                    "purpose": key_purpose,
                    "type": "public",
                    "value": TEST_DO_NOT_USE_UPSTREAM_PUBLIC_PEM,
                    "service": "some-service",
                },
                "KID_FOR_EQ_V2": {
                    "purpose": key_purpose,
                    "type": "public",
                    "value": TEST_DO_NOT_USE_PUBLIC_KEY,
                    "service": "eq_v2",
                },
            }
        }
    )
