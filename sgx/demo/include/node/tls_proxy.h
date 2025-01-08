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
  {"ecdh-server-port", required_argument, 0, 'p'},
  {"ecdh-server-key", required_argument, 0, 'k'},
  {"ecdh-server-cert", required_argument, 0, 'c'},
  {"ecdh-client-cert", required_argument, 0, 'u'},
  // TLS connection info
  {"tls-server-host", required_argument, 0, 'I'},
  {"tls-server-port", required_argument, 0, 'P'},
  {"tls-server-san", required_argument, 0, 'N'},
  {"tls-client-key", required_argument, 0, 'R'},
  {"tls-client-cert", required_argument, 0, 'U'},
  // Certificate Authority (CA) info
  {"ca-cert", required_argument, 0, 'C'},
  // Test options
  {"maxconn", required_argument, 0, 'm'},
  // Misc
  {"help", no_argument, 0, 'h'},
  {0, 0, 0, 0}
};

#endif // KMYTH_TLS_PROXY_H
