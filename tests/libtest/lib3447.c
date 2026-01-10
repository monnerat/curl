/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

#define FILESIZE    (220 * (76 + 1))


static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  unsigned int *countptr = userp;

  size *= nmemb;
  for(nmemb = 0; nmemb < size; nmemb++) {
    if(*countptr >= FILESIZE)
      break;
    ptr[nmemb] = (char) ('A' + *countptr % 26);
    if(!(++*countptr % (76 + 1)))
      ptr[nmemb] = '\n';
  }
  return nmemb;
}

static CURLcode test_lib3447(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  unsigned int count = 0;

  /* Checks large sieve script transfers with small buffers. */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    result = (CURLcode) TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  /* Shorten buffers. */
  test_setopt(curl, CURLOPT_BUFFERSIZE, 8192L);
  test_setopt(curl, CURLOPT_UPLOAD_BUFFERSIZE, 8192L);

  /* Set the URL that targets the remote script. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* Prepare to read data (for upload). */
  test_setopt(curl, CURLOPT_INFILESIZE, (long) FILESIZE);
  test_setopt(curl, CURLOPT_READFUNCTION, read_cb);
  test_setopt(curl, CURLOPT_READDATA, &count);

  if(testnum == 3448) {
    /* This is an upload. */
    test_setopt(curl, CURLOPT_UPLOAD, 1L);
  }

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* Perform the request, result will get the return code */
  result = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
