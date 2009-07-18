// packet-protobufs.cpp: wireshark module using Protobuf Reflection
// Copyright 2009 Patrick Reiter Horn. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Sirikata nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdio.h>
#include <glib.h>

extern "C" {
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <epan/packet.h>
}

#include <string.h>

#include <string>

extern gint ett_proto_str, ett_proto_msg, ett_proto_int, ett_proto_float;
extern gint hf_proto_str, hf_proto_msg, hf_proto_int, hf_proto_float;
extern gint ett_sst_data;

#if 0 //def HAVE_PROTOBUFS
#include <google/protobuf/message.h>

using namespace google::protobuf;

void parse_protobufs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	gint length = tvb_length(tvb);
	char *full_buffer = new char[length];
	tvb_memcpy(tvb, full_buffer, 0, length);

	Message msg;
	msg.ParseFromArray(full_buffer, length);

	const Reflection* reflect = msg.GetReflection();
	
}
#else /* HAVE_PROTOBUFS */

template <class NumType>
static NumType parse_varnum(tvbuff_t *tvb, gint *offset, gint length) {
	NumType retval = 0;
	int numbits = sizeof(NumType)*8;
	int shift = 0;
	while (numbits > 0 && length > 0) {
		guint8 byte = tvb_get_guint8(tvb, *offset);
		++*offset;
		--length;

		retval |= ((byte & 127) << shift);
		shift += 7;

		if (!(byte & 128)) {
			break;
		}
		numbits -= 7;
	}
	return retval;
}

bool parse_protobufs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	gint offset = 0;
	gint length = tvb_length(tvb);
	while (offset < length) {
		guint32 field = parse_varnum<guint32>(tvb, &offset, length-offset);
		guint8 type = (field&7);
		field >>=3;
		if (field >= 0x800000) {
//			printf("Error: field ID %u too high *before* offset %d\n", field, offset);
			return false;
		}
		std::string desc;
		switch (type) {
		case 0:
			{
				gint orig_offset = offset;
				guint64 value = parse_varnum<guint64>(tvb, &offset, length-offset);
				if (tree) {
					proto_tree_add_uint64_format(tree, hf_proto_int, tvb, orig_offset, offset-orig_offset, value, "%d: %lld [%d-bit]", field, (long long int)value, ((offset-orig_offset)*7));
				}
			}
			break;
		case 1:
		    if (length-offset >= 8){
				guint64 value = tvb_get_ntoh64(tvb, offset);
				guint64 flipvalue = tvb_get_letoh64(tvb, offset);
				gdouble fltvalue = *(gdouble*)&flipvalue;
				if (tree) {
					guint64 unsignedflipvalue = (flipvalue&0x7fffffffffffffffULL);
					if (unsignedflipvalue >= 0x7FF0000000000000ULL) {
						const char *signstr = "";
						if (unsignedflipvalue != flipvalue) {
							signstr = "-";
						}
						const char *message="?";
						if (flipvalue == 0xFFF8000000000000U) {
							message = "Indeterminite NaN";
							signstr = "";
						} else if (unsignedflipvalue >= 0x7FF8000000000001LL && unsignedflipvalue <= 0x7FFFFFFFFFFFFFFFLL) {
							message = "Quiet NaN";
						} else if (unsignedflipvalue >= 0x7FF0000000000001LL && unsignedflipvalue <= 0x7FF7FFFFFFFFFFFFLL) {
							message = "Signalling NaN";
						} else if (unsignedflipvalue == 0x7FF0000000000000LL) {
							message = "Infinity";
						}
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 8, value, "%d: 0x%08llX [%s%s Double]", field, (long long int)value, signstr, message);
					} else if (fltvalue > -1e+8 && fltvalue < 1e+8 && (fltvalue > 1e-8 || fltvalue < -1e-8)) {
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 8, value, "%d: %lf", field, fltvalue);
					} else {
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 8, value, "%d: %lld", field, (long long int)value);
					}
				}
				offset += 8;
			} else {
//				printf("Aborting parse: got 64-bit at offset %d, but only %d left\n", offset, length-offset);
				return false;
			}
			break;
		case 2:
			{
				guint32 slen = parse_varnum<guint32>(tvb, &offset, length-offset);
				if (length-offset < slen){
//					printf("Aborting parse: got string len %d at offset %d, but only %d left\n", slen, offset, length-offset);
					return false;
				}
				if (tree) {
					tvbuff_t *sub_tvbuff = NULL;
					if (slen > 0) {
						sub_tvbuff = tvb_new_subset(tvb, offset, slen, slen);
					}
					if (!sub_tvbuff) {
						guint8 mystr[1];
						mystr[0]=0;
						proto_tree_add_bytes_format(tree, hf_proto_str, tvb, offset, 0, mystr, "%d: Empty String", field);
					} else if (parse_protobufs(sub_tvbuff, pinfo, NULL)) {
						proto_item * iTem = proto_tree_add_none_format(tree, hf_proto_msg, tvb, offset, slen, "%d: Embedded Message (%d bytes)", field, slen);
						proto_tree * sTree = proto_item_add_subtree(iTem, ett_proto_msg);
						parse_protobufs(sub_tvbuff, pinfo, sTree);
					} else {
						guint8 *mystr = new guint8[slen+1];
						tvb_memcpy(tvb, mystr, offset, slen);
						mystr[slen]='\0';
						bool isuuid=false;
						if (slen <= 16 && slen > 4) {
							for (int i = 0; i < slen; ++i) {
								if ((mystr[i] < 32 && !isspace(mystr[i])) || mystr[i] >= 127) {
									isuuid = true;
									break;
								}
							}
						}
						if (isuuid && slen <= 16) {
							guint8 tmpbuf[16];
							memset(tmpbuf, 0, 16);
							tvb_memcpy(tvb, tmpbuf, offset, slen);
							tvbuff_t *tvb_temp = tvb_new_real_data(tmpbuf, 16, 16);
							e_guid_t uuid;
							tvb_get_guid(tvb_temp, 0, &uuid, FALSE);
							tvb_free(tvb_temp);
							char strbuf[80];
							guid_to_str_buf(&uuid, strbuf, 70);
							proto_tree_add_bytes_format(tree, hf_proto_str, tvb, offset, slen, mystr, "%d: UUID %s", field, strbuf);
						} else if (slen < 500) {
							proto_tree_add_bytes_format(tree, hf_proto_str, tvb, offset, slen, mystr, "%d: String (%d bytes): %s", field, slen, mystr);
						} else {
							guint8 tmpbuf[501];
							memcpy(tmpbuf, mystr, 500);
							tmpbuf[500]='\0';
							proto_tree_add_bytes_format(tree, hf_proto_str, tvb, offset, slen, mystr, "%d: String (%d bytes): %s...", field, slen, tmpbuf);
						}
						delete []mystr;
					}
					if (sub_tvbuff) {
//						tvb_free(sub_tvbuff);
					}
				}

				offset += slen;
			}
			break;
		case 5:
			if (length-offset >= 4){
				guint32 value = tvb_get_ntohl(tvb, offset);
				guint32 flipvalue = tvb_get_letohl(tvb, offset);
				gfloat fltvalue = *(gfloat*)&flipvalue;
				if (tree) {
					guint32 unsignedflipvalue = (flipvalue&0x7fffffffULL);
					if (unsignedflipvalue >= 0x7F800000) {
						const char *signstr = "";
						if (unsignedflipvalue != flipvalue) {
							signstr = "-";
						}
						const char *message="?";
						if (flipvalue == 0xFFC00000U) {
							message = "Indeterminite NaN";
							signstr = "";
						} else if (unsignedflipvalue >= 0x7FC00000 && unsignedflipvalue <= 0x7FFFFFFF) {
							message = "Quiet NaN";
						} else if (unsignedflipvalue >= 0x7F800001 && unsignedflipvalue <= 0x7FBFFFFF) {
							message = "Signalling NaN";
						} else if (unsignedflipvalue == 0x7F800000) {
							message = "Infinity";
						}
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 4, (guint64)value, "%d: 0x%08X [%s%s Float]", field, value, signstr, message);
					} else if (fltvalue > -1e+8 && fltvalue < 1e+8 && (fltvalue > 1e-8 || fltvalue < -1e-8)) {
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 4, (guint64)value, "%d: %f", field, fltvalue);
					} else {
						proto_tree_add_uint64_format(tree, hf_proto_int, tvb, offset, 4, (guint64)value, "%d: %d", field, value);
					}
				}
				offset += 4;
			} else {
//				printf("Aborting parse: got 32-bit at offset %d, but only %d left\n", offset, length-offset);
				return false;
			}
			break;
		default:
//		  printf("Aborting parse: got unknown type %d offset %d\n", (int)type, offset);
			return false;
		}
	}
	return true;
}

#endif
