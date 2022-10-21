/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2018  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  EFI TPM pass-through commands.
 */

#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/mm.h>

#include <tss2/tss2_tpm2_types.h>

struct tpm2_command_header {
  TPMI_ST_COMMAND_TAG tag;
  UINT32 commandSize;
  TPM2_CC commandCode;
} GRUB_PACKED;

struct tpm2_response_header {
  TPM2_ST tag;
  UINT32 responseSize;
  TPM2_RC responseCode;
} GRUB_PACKED;

#define SIZED_BUFFER(n) \
  struct { UINT16 size; unsigned char[(n)] buffer; } GRUB_PACKED

/* SHA512 should currently have the largest digest size */
#define MAX_DIGEST_SIZE TPM2_SHA512_DIGEST_SIZE

grub_err_t grub_tpm2_get_random (unsigned char *buffer, grub_size_t size)
{
  struct {
    struct tpm2_command_header header;
    UINT16 bytesRequested;
  } GRUB_PACKED *command = NULL;
  struct {
    struct tpm2_response_header header;
    SIZED_BUFFER(MAX_DIGEST_SIZE) randomBytes;
  } GRUB_PACKED *response = NULL;
  grub_err_t status = GRUB_ERR_NONE;

  if (!buffer)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("missing buffer for random bytes"));

  if (size > DIGEST_MAX_SIZE)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("cannot get more than %d random bytes per call"),
                       DIGEST_MAX_SIZE);

  command = grub_zalloc (command_size);
  response = grub_zalloc (response_size);
  if (!command || !response) {
    status = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                         N_("cannot allocate TPM buffers"));
    goto done;
  }

  command->header.tag = grub_cpu_to_be16 (TPM2_ST_NO_SESSIONS);
  command->header.commandSize = grub_cpu_to_be32 (sizeof (*command));
  command->header.commandCode = grub_cpu_to_be32 (TPM2_CC_GetRandom);
  command->bytesRequested = grub_cpu_to_be16 (size);

  status = grub_tpm2_submit_command (command, sizeof (*command),
                                     response, sizeof (*response));
  if (status != GRUB_ERROR_NONE)
    goto done;

  if (response_code != TPM2_RC_SUCCESS) {
    status = grub_error (GRUB_ERR_IO, N_("TPM error %d"), response_code);
    goto done;
  }

  memcpy (buffer, response->randomBytes.buffer, response->randomBytes.size);

 done:
  if (command)
    grub_free (command);
  if (response)
    grub_free (response);
  return status;
}

grub_err_t grub_tpm2_start_auth_session (grub_uint32_t *handle)
{
  /* We hardcode SHA256 here */
  const TPMI_ALG_HASH hash_alg = TPM2_ALG_SHA256;
  grub_size_t nonce_size = TPM2_SHA256_DIGEST_SIZE;
  struct {
    struct tpm2_command_header header;
    TPMI_DH_OBJECT tpmKey;
    TPMI_DH_ENTITY bind;
    SIZED_BUFFER(nonce_size) nonceCaller;
    SIZED_BUFFER(0) encryptedSalt;
    TPM_SE sessionType;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
  } GRUB_PACKED *command;
  struct {
    struct tpm2_response_header header;
    TPMI_SH_AUTH_SESSION sessionHandle;
    SIZED_BUFFER(MAX_DIGEST_SIZE) nonceTPM;
  } GRUB_PACKED *response;
  grub_uint32_t command_size = sizeof (*command);
  grub_uint32_t response_size = sizeof (*response);
  grub_uint32_t response_code;
  grub_err_t status = GRUB_ERR_NONE;

  if (!handle)
    return grub_error (GRUB_BAD_ARGUMENT,
                       N_("must provide handle buffer"));

  command = grub_zalloc (command_size);
  response = grub_zalloc (response_size);
  if (!command || !response) {
    status = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                         N_("cannot allocate TPM buffers"));
    goto done;
  }

  command->header.tag = grub_cpu_to_be16 (TPM2_ST_NO_SESSIONS);
  command->header.commandSize = grub_cpu_to_be32 (command_size);
  command->header.commandCode = grub_cpu_to_be32 (TPM2_CC_StartAuthSession);
  command->tpmKey = grub_cpu_to_be32 (TPM2_RH_NULL);
  command->bind = grub_cpu_to_be32 (TPM2_RH_NULL);
  command->nonceCaller.size = grub_cpu_to_be16 (nonce_size);
  command->encryptedSalt.size = grub_cpu_to_be16 (0);
  command->sessionType = TPM2_SE_HMAC;
  command->symmetric = grub_cpu_to_be16 (TPM2_ALG_NULL);
  command->authHash = grub_cpu_to_be16 (hash_alg);

  status = grub_tpm2_get_random (command->nonceCaller.buffer, nonce_size);
  if (status != GRUB_ERR_NONE)
    goto done;

  status = grub_tpm2_submit_command (command, command_size,
                                     response, response_size);
  if (status != GRUB_ERROR_NONE)
    goto done;

  response_code = grub_be_to_cpu32 (response->responseCode);

  if (response_code != TPM2_RC_SUCCESS) {
    status = grub_error (GRUB_ERR_IO, N_("TPM error %d"), response_code);
    goto done;
  }

  *handle = grub_be_to_cpu32 (response->sessionHandle);

 done:
  if (command)
    grub_free (command);
  if (response)
    grub_free (response);
  return status;
}

grub_err_t grub_tpm2_create_primary (grub_uint32_t session_handle,
                                     unsigned char *sensitive,
                                     grub_size_t sensitive_size)
{
  struct {
    struct tpm2_command_header header;
    TPMI_RH_HIERARCHY primaryHandle;
    struct {
      UINT32 size;
      UINT32 sessionHandle;
      SIZED_BUFFER(0) nonce;
      TPMA_SESSION sessionAttributes;
      SIZED_BUFFER(0) hmac;
    } GRUB_PACKED auth;
    struct {
      UINT16 size;
      SIZED_BUFFER(0) userAuth;
      SIZED_BUFFER(0) data;
    } GRUB_PACKED inSensitive;
    struct {
      UINT16 size;
      struct {
        TPMI_ALG_PUBLIC type;
        TPMI_ALG_HASH nameAlg;
        TPMA_OBJECT objectAttributes;
        SIZED_BUFFER(0) authPolicy;
        TPMU_PUBLIC_PARMS parameters;
        TPMU_PUBLIC_ID unique;
      } GRUB_PACKED publicArea;
    } GRUB_PACKED inPublic;
    SIZED_BUFFER(0) outsideInfo;
    TPML_PCR_SELECTION creationPCR;
  } GRUB_PACKED *command;
  struct {
    struct tpm2_response_header header;
    TPM_RC responseCode;
    TPM_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
  } GRUB_PACKED *response;
  grub_size_t command_size = sizeof (*command);
  grub_size_t response_size = sizeof (*response);

  command = grub_zalloc (command_size);
  response = grub_zalloc (response_size);
  if (!command || !response) {
    status = grub_error (GRUB_ERR_OUT_OF_MEMORY,
                         N_("cannot allocate TPM buffers"));
    goto done;
  }

  command->header.tag = grub_cpu_to_be16 (TPM2_ST_SESSIONS);
  command->header.commandSize = grub_cpu_to_be32 (command_size);
  command->header.commandCode = grub_cpu_to_be32 (TPM2_CC_CreatePrimary);
  command->primaryHandle = grub_cpu_to_be32 (TPM2_RH_ENDORSEMENT);
  command->auth.size = grub_cpu_to_be32 (sizeof (command->auth) - 4);
  command->auth.sessionHandle = grub_cpu_to_be32 (session_handle);
  command->inSensitive.size = grub_cpu_to_be16 (sizeof (command->inSensitive) - 2);
  command->inPublic.size = grub_cpu_to_be16 (sizeof (command->inPublic) - 2);

  status = grub_tpm2_submit_command ((unsigned char *) command, command_size,
                                     (unsigned char *) response, response_size);

 done:
  if (command)
    grub_free (command);
  if (response)
    grub_free (response);
  return status;
}

