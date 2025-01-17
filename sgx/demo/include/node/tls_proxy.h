/**
 * @file  tls_proxy.h
 *
 * @brief Provides global constants, structs, and function declarations
 *        for the TLS proxy test application.
 */

#ifndef KMYTH_TLS_PROXY_H
#define KMYTH_TLS_PROXY_H

#include <poll.h>

#include "retrieve_key_protocol.h"

#include "demo_ecdh_util.h"
#include "demo_tls_util.h"
#include "tls_util.h"

/**
 * @brief This struct consolidates complete (overall) state information
 *        required for a 'TLS Proxy' node to complete the kmyth
 *        'retrieve key' protocol. This proxy bridges an ECDH and a TLS
 *        connection and contains interfaces for a TLS client and an
 *        ECDH server.
 */
typedef struct TLSProxy
{
  TLSPeer tlsconn;
  ECDHPeer ecdhconn;
} TLSProxy;

/**
 * @brief Command-line options for the 'TLS proxy' application
 */
static const struct option proxy_longopts[] = {
  // ECDH connection info
  {"ecdh-port", required_argument, 0, 'p'},
  {"ecdh-local-key", required_argument, 0, 'k'},
  {"ecdh-local-cert", required_argument, 0, 'l'},
  {"ecdh-remote-cert", required_argument, 0, 'r'},
  // TLS connection info
  {"tls-port", required_argument, 0, 'P'},
  {"tls-local-key", required_argument, 0, 'K'},
  {"tls-local-cert", required_argument, 0, 'L'},
  {"tls-remote-host", required_argument, 0, 'R'},
  // Certificate Authority (CA) info
  {"ca-cert", required_argument, 0, 'C'},
  // Test options
  {"maxconn", required_argument, 0, 'm'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

#endif // KMYTH_TLS_PROXY_H
