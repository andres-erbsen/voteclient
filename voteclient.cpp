// Written by Andres Erbsen, distributed under GPLv3 with the OpenSSL exception

#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <sstream>
#include <iostream>

#include <curl/curl.h>

#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <smartcardpp/smartcardpp.h>

#include <lsags.h>

// ugly hack: pause at end so windows (GUI) users see output of last command
#if defined _WIN32 || defined _WIN64
# define PAUSE() getchar()
#else
# define PAUSE() do {} while (0)
#endif

#define die(x) do {\
  fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, x);\
  PAUSE();\
  exit(1);\
} while (0)

#define FILETYPE_TAG_SIZE 8
#define EL_TAG_SIZE (8+8+16)
#define FILE_TAG_SIZE (FILETYPE_TAG_SIZE+EL_TAG_SIZE)
#define VOUCHER_TYPE_RSASHA1 7
#define SERVER_CERT_PATH "e-voting-server.pem"

//////// Encoding/decoding functions ////////
template <typename T> std::string str(T n) { // str(3) = "3"
  std::ostringstream ss;
  ss << n;
  return ss.str();
}

template <typename T> std::string le_bytes(T n) { // le_bytes(uint16_t(1)) = "\1\0"
  std::string ret(sizeof(T), '\0');
  for (int i=0; i<sizeof(T); ++i) {
    ret[i] = n & 0xff;
    n >>= 8;
  }
  return ret;
}

uint16_t uint16le(void* p_) { // uint16le("\1\0") = 1
  unsigned char* p = (unsigned char*) p_;
  return (uint16_t) (*(p+1) << 8) | (uint16_t) *p;
}

uint64_t uint64le(void *p_) { // uint64le("\1\0\0\0\0\0\0\0") = 1
  unsigned char* p = (unsigned char*) p_;
  uint64_t ret = 0;
  ret |= (uint64_t)*p++;
  ret |= (uint64_t)*p++ << 8;
  ret |= (uint64_t)*p++ << 16;
  ret |= (uint64_t)*p++ << 24;
  ret |= (uint64_t)*p++ << 32;
  ret |= (uint64_t)*p++ << 40;
  ret |= (uint64_t)*p++ << 48;
  ret |= (uint64_t)*p++ << 56;
  return ret;
}

//////// HTTP functions ////////
size_t private_curl_write_to_string(char *ptr, size_t size, size_t nmemb, void *userdata) {
  ((std::string*) userdata)->append(ptr, nmemb*size);
  return nmemb*size;
}

CURLcode httpPOST(const std::string url, const std::string postdata, std::string* ret) {
  CURL *curl = curl_easy_init();
  if (curl == NULL) return CURLE_OUT_OF_MEMORY;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CAINFO, SERVER_CERT_PATH);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.data());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE , postdata.size());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, private_curl_write_to_string);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ret);
  CURLcode retcode = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  return retcode;
}

CURLcode httpGET(const std::string url, std::string* ret) {
  CURL *curl = curl_easy_init();
  if (curl == NULL) return CURLE_OUT_OF_MEMORY;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_CAINFO, SERVER_CERT_PATH);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, private_curl_write_to_string);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, ret);
  CURLcode retcode = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  return retcode;
}


int RSA_SHA256_verify(const std::string& msg, const std::string& sig, RSA* pk) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char*)msg.data(), msg.size(), hash);
  return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
      (unsigned char*) sig.data(), sig.size(), pk);
}

std::string ask(const std::string& prompt) {
  std::cout << prompt;
  std::string ret;
  std::getline(std::cin, ret);
  return ret;
}

int writeFile(const std::string& filename, const std::string& data) {
    FILE* f = fopen(filename.c_str(), "wb");
    if (f == NULL) return 0;
    if (fwrite(data.data(), 1, data.size(), f) != data.size()) return 0;
    if (fclose(f) != 0) return 0;
    return 1;
}

int main(int argc, char** argv) {
  if ( argc > 2) die("Usage: voteclient [paranoid]");
  bool paranoid = (argc == 2 && std::string(argv[1]) == "paranoid");

  std::string VOTE_SERVER_URL(ask("Server address: "));
  if (VOTE_SERVER_URL.find("://") == std::string::npos) VOTE_SERVER_URL.insert(0,"https://");
  if (*VOTE_SERVER_URL.rbegin() != '/') VOTE_SERVER_URL.append("/");
  curl_global_init(CURL_GLOBAL_ALL);

  // TODO: get server certificate from itself, verify using SSL PKI
  RSA *server_rsa_pk = NULL;
  { // load server RSA public key to global variable
    X509* x = NULL;
    EVP_PKEY *pkey = NULL;
    FILE* f = fopen(SERVER_CERT_PATH, "r");
    if (f == NULL) die("Could not read server certificate from " SERVER_CERT_PATH ".");
    x = PEM_read_X509(f, NULL, NULL, NULL);
    if (x == NULL) die("Invalid certificate file " SERVER_CERT_PATH ".");
    pkey = X509_get_pubkey(x);
    X509_free(x);
    if (pkey == NULL) die("No public key in certificate file" SERVER_CERT_PATH ".");
    server_rsa_pk = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (server_rsa_pk == NULL) die("No RSA public key in certificate file" SERVER_CERT_PATH ".");
  }

  PCSCManager mgr;
  mgr.setLogging(&std::cerr);
  if (mgr.getReaderCount() == 0) die("No card reader found.");

  std::string election_status;
  CURLcode curl_err;
  if ((curl_err = httpGET(VOTE_SERVER_URL+"status", &election_status)) != CURLE_OK) {
    std::cerr << "curl: " << curl_easy_strerror(curl_err) << std::endl;
    die("Cannot connect to server");
  }

  uint reader = 0;
  try {
    EstEidCard eidCard(mgr, reader);
    if (!eidCard.isInReader(reader)) die("No ID card found.");

    uint64_t voter_id = 0;
    voter_id = strtoll(eidCard.readCardID().c_str(), NULL, 10);

    unsigned char sk[LSAGS_SK_SIZE];
    unsigned char pk[LSAGS_PK_SIZE];

    if (election_status == "REG") {
      std::cout << "Preparing to register as " << voter_id << std::endl;
      if (!LSAGS_keygen(sk, pk)) die("Failed to generate LSAGS keypair");

      // encrypt our secret key to our id card, we'll send it to server later
      std::vector<unsigned char> cargo;
      std::cout << "Loading data from ID card" << std::endl;
      {
        RSA *rsa_pk = NULL;
        EVP_PKEY *pkey = NULL;
        X509* x = NULL;
        const ByteVec cert_der = eidCard.getAuthCert();
        const unsigned char* der_ptr = &cert_der[0];
        x = d2i_X509(NULL, &der_ptr, cert_der.size());
        if (x == NULL) die ("Failed to load certificate from ID card.");
        pkey = X509_get_pubkey(x);
        X509_free(x);
        rsa_pk = EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
        if (rsa_pk == NULL) die ("Failed to load certificate from ID card.");
        cargo.resize(RSA_size(rsa_pk));
        RSA_public_encrypt(LSAGS_SK_SIZE, sk, &cargo[0], rsa_pk, RSA_PKCS1_PADDING);
        RSA_free(rsa_pk);
      }


      std::vector<unsigned char> hash(20);
      SHA1(pk, LSAGS_PK_SIZE, &hash[0]);
      ByteVec sig = eidCard.calcSignSHA1(hash, EstEidCard::AUTH,  PinString(ask("PIN1: ").c_str()));

      { // check that the cargo decrypts ok before sending it, just in case
        std::vector<unsigned char> sk_back = eidCard.RSADecrypt(cargo);
        if (memcmp(sk, &sk_back[0], LSAGS_SK_SIZE)) die ("Encrypt to self and decrypt - doesn't work.");
      }
      
      std::string registration = le_bytes(voter_id) + le_bytes(uint8_t(VOUCHER_TYPE_RSASHA1));
        registration.append(le_bytes(uint16_t(sig.size())));
        registration.append(sig.begin(), sig.end());
        registration.append((char*)pk, LSAGS_PK_SIZE);
        registration.append(cargo.begin(), cargo.end());
      std::string rrec(std::string("REGISTER")+registration), rrec_sig;
      if ( httpPOST(VOTE_SERVER_URL+"register", registration, &rrec_sig) != CURLE_OK
        || !RSA_SHA256_verify(rrec, rrec_sig, server_rsa_pk)) {
        die("Could not register for voting");
      }
      std::cout << "The election authority has received your registration and promised to allow us to vote" << std::endl;
      if (paranoid) { writeFile("reg", rrec); writeFile("reg.sig", rrec_sig); }
    } else if (election_status == "VOTE") {
      std::cout << "Preparing to vote as " << voter_id << std::endl;

      // download description of groups
      std::string groups, groups_sig;
      if ( httpGET(VOTE_SERVER_URL+"groups/groups" , &groups) != CURLE_OK
        || groups.size() < FILE_TAG_SIZE+8
        || groups.substr(0,FILETYPE_TAG_SIZE) != "GROUPSLL"
        || httpGET(VOTE_SERVER_URL+"groups/groups.sig", &groups_sig) != CURLE_OK
        || !RSA_SHA256_verify(groups, groups_sig, server_rsa_pk)) {
        die("Failed to retrieve groups list from server");
      }
      if (paranoid) { writeFile("groups", groups); writeFile("groups.sig", groups_sig); }

      // is it really the one for today's election?
      uint64_t start_time = uint64le(&groups[FILETYPE_TAG_SIZE]);
      uint64_t current_time = time(NULL);
      uint64_t end_time = uint64le(&groups[FILETYPE_TAG_SIZE+8]);
      const std::string election_tag = groups.substr(FILETYPE_TAG_SIZE,EL_TAG_SIZE);
      if (current_time < start_time || current_time >= end_time) die("No election in progress");

      int group = -1;
      // parse groups' lists of members, determine ours
      {
        char *p = &groups[0]+FILE_TAG_SIZE, *end = &groups[0] + groups.size();
        int n = 0;
        while (p + 8 <= end) {
          if (n == 0) {
            group++;
            n = uint64le(p);
          } else {
            n--;
            if (uint64le(p) == voter_id) {
              break;
            }
          }
          p += 8;
        }
      }

      // download group members' public keys and cargos
      if (group < 0) die ("We don't seem to be invited to this election");
      std::string pks, cargos, pks_sig, cargos_sig;
      if ( httpGET(VOTE_SERVER_URL+"groups/" + str(group) + ".pks" , &pks) != CURLE_OK
        || pks.size() < FILE_TAG_SIZE+8
        || pks.substr(0,FILETYPE_TAG_SIZE) != "GROUPPKS"
        || pks.substr(FILETYPE_TAG_SIZE,EL_TAG_SIZE) != election_tag
        || uint64le(&pks[FILE_TAG_SIZE]) != group
        || httpGET(VOTE_SERVER_URL+"groups/" + str(group) + ".pks.sig", &pks_sig) != CURLE_OK
        || !RSA_SHA256_verify(pks, pks_sig, server_rsa_pk)) {
        die("Failed to retrieve group public keys from server");
      }
      if (paranoid) { writeFile("pks", pks); writeFile("pks.sig", pks_sig); }
      pks = pks.substr(FILE_TAG_SIZE+8);
      if (pks.size()%LSAGS_PK_SIZE) die("Bad pks list");

      if ( httpGET(VOTE_SERVER_URL+"groups/" + str(group) + ".cargos" , &cargos) != CURLE_OK
        || cargos.size() < FILE_TAG_SIZE+8+LSAGS_SK_SIZE
        || cargos.substr(0,FILETYPE_TAG_SIZE) != "GROUPCGS"
        || cargos.substr(FILETYPE_TAG_SIZE,EL_TAG_SIZE) != election_tag
        || uint64le(&cargos[FILE_TAG_SIZE]) != group
        || httpGET(VOTE_SERVER_URL+"groups/" + str(group) + ".cargos.sig", &cargos_sig) != CURLE_OK
        || !RSA_SHA256_verify(cargos, cargos_sig, server_rsa_pk)) {
        die("Failed to retrieve group cargos from server");
      }
      if (paranoid) { writeFile("cargos", cargos); writeFile("cargos.sig", cargos_sig); }
      cargos = cargos.substr(FILE_TAG_SIZE+8);

      // get our cargo
      std::string cargo;
      { 
        char *p = &cargos[0], *end = &cargos[0] + cargos.size();
        while (p + 10 <= end) {
          uint64_t owner = uint64le(p); p += 8;
          uint16_t size = uint16le(p); p += 2;
          if (owner == voter_id) {
            if (p + size > end) die("Got bad cargos from server");
            cargo = std::string(p, size);
            break;
          }
          p += size;
        }
      }

      std::cout << "Verifying ID card..." << std::endl;
      // decrypt our cargo to get the LSAGS secret key
      std::vector<unsigned char> sk = eidCard.RSADecrypt(ByteVec(cargo.begin(), cargo.end()), PinString(ask("PIN1: ").c_str()));
      if (sk.size() != LSAGS_SK_SIZE) die("Bad cargo");
      std::string sig(LSAGS_sig_size(pks.size()/LSAGS_PK_SIZE), '\0');
      std::string vote(ask("Please enter your vote: "));
      std::cout << "Generating an anonymous vote..." << std::endl;
      if (!LSAGS_sign( (unsigned char*) &pks[0], pks.size(),
            (unsigned char*) &sk[0],
            (unsigned char*) &vote[0], vote.size(),
            (unsigned char*) election_tag.data(), election_tag.size(),
            (unsigned char*) &sig[0], NULL)) {
          die("Failed to sign the vote");
      }

      std::string signed_vote( le_bytes(uint16_t(vote.size())) + vote + sig );
      std::string vrec("VOTEVOTE" + election_tag + le_bytes(uint64_t(group)) + signed_vote);
      std::string vrec_sig;

      if ( httpPOST(VOTE_SERVER_URL+"votes/" + str(group), signed_vote, &vrec_sig) != CURLE_OK
        || !RSA_SHA256_verify(vrec, vrec_sig, server_rsa_pk)) {
        die("Could not deliver vote");
      }
      if (paranoid) { writeFile("vrec", vrec); writeFile("vrec.sig", vrec_sig); }

      std::cout << "The election authority received your vote and promised to count it." << std::endl;
    }
  } catch(std::runtime_error &e) {die(e.what());}

  RSA_free(server_rsa_pk);
  curl_global_cleanup();
  PAUSE();
  return 0;
}
