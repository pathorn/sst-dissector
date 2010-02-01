/*
 * SST Dissector for Wireshark.
 *
 * heur_dissect_sst is copyright (C) 2009 Patrick Reiter Horn
 * and is licensed under BSD.
 *
 * Skeleton code thanks to Ken Thompson
 * http://www.codeproject.com/KB/IP/custom_dissector.aspx
 */

#include <stdio.h>
#include <glib.h>

extern "C" {
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <epan/packet.h>
#include <epan/strutil.h>
}

#include <string.h>

#define PROTO_TAG_SST "SST"

static int proto_sst = -1;

static dissector_handle_t data_handle=NULL;
static dissector_handle_t sst_handle=NULL;

static gboolean process_websocket_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, proto_tree *sst_tree);
static gboolean detect_websocket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gboolean process_tcpsst_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, proto_tree *sst_tree);
static gboolean detect_tcpsst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


extern "C"
gboolean heur_dissect_sst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

extern "C"
void dissect_sst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	(void)heur_dissect_sst(tvb, pinfo, tree);
}

void parse_protobufs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint hf_sst = -1;
static gint hf_sst_packet = -1;
static gint hf_sst_sid = -1;
static gint hf_sst_length = -1;
static gint hf_sst_end = -1;
static gint hf_sst_data = -1;
static gint hf_sst_toplevel = -1;
static gint hf_sst_connid = -1;
static gint hf_sst_uuid = -1;
gint hf_proto_str = -1;
gint hf_proto_msg = -1;
gint hf_proto_int = -1;


/* These are the ids of the subtrees that we may be creating */
static gint ett_sst = -1;
static gint ett_sst_packet = -1;
static gint ett_sst_sid = -1;
static gint ett_sst_length = -1;
static gint ett_sst_end = -1;
gint ett_sst_data = -1;
static gint ett_sst_toplevel = -1;
static gint ett_sst_connid = -1;
static gint ett_sst_uuid = -1;
gint ett_proto_str = -1;
gint ett_proto_msg = -1;
gint ett_proto_int = -1;

extern "C"
void proto_reg_handoff_sst(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		data_handle = find_dissector("data");
		sst_handle = create_dissector_handle(dissect_sst, proto_sst);
	}
}

extern "C"
void proto_register_sst (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_sst,
		{ "SST Packet", "sst.root", FT_NONE, BASE_NONE, NULL, 0x0,
		  "SST", HFILL }},
		{ &hf_sst_packet,
		{ "Substream", "sst.packet", FT_NONE, BASE_NONE, NULL, 0x0,
		  "Substream", HFILL }},
		{ &hf_sst_length,
		{ "Length", "sst.len", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Packet Length", HFILL }},
		{ &hf_sst_sid,
		{ "Stream ID", "sst.sid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Stream ID", HFILL }},
		{ &hf_sst_end,
		{ "End", "sst.end", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Ending", HFILL }},
		{ &hf_sst_data,
		{ "Data", "sst.data", FT_NONE, BASE_NONE, NULL, 0x0,
		  "Data", HFILL }},
		{ &hf_sst_toplevel,
		{ "Top-Level Stream", "sst.toplevel", FT_NONE, BASE_NONE, NULL, 0x0,
		  "Top-Level Stream", HFILL }},
		{ &hf_sst_connid,
		{ "Connection Number", "sst.connid", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Connection Number", HFILL }},
		{ &hf_sst_uuid,
		{ "Top-Level UUID", "sst.uuid", FT_GUID, BASE_NONE, NULL, 0x0,
		  "Top-Level UUID", HFILL }},
		{ &hf_proto_str,
		{ "Proto String", "protobuf.field", FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Protocol Buffers String", HFILL }},
		{ &hf_proto_msg,
		{ "Embedded Message", "protobuf.message", FT_NONE, BASE_NONE, NULL, 0x0,
		  "Embedded Protocol Buffers Message", HFILL }},
		{ &hf_proto_int,
		{ "Proto Int", "protobuf.int", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Protocol Buffers Int64", HFILL }}
	};

	static gint *ett[] = {
		&ett_sst,
		&ett_sst_packet,
		&ett_sst_sid,
		&ett_sst_length,
		&ett_sst_end,
		&ett_sst_data,
		&ett_sst_toplevel,
		&ett_sst_connid,
		&ett_sst_uuid,
		&ett_proto_str,
		&ett_proto_msg,
		&ett_proto_int
	};

	 proto_sst = proto_register_protocol ("Structured Stream Transport", PROTO_TAG_SST, "sst");

	 proto_register_field_array (proto_sst, hf, array_length (hf));
	 proto_register_subtree_array (ett, array_length (ett));
	 heur_dissector_add("tcp", heur_dissect_sst, proto_sst);
}

#include <map>
#include <set>
#include <string>

bool operator<(const address &adr1, const address &adr2) {
	if (adr1.type != adr2.type) {
		return (int)adr1.type < (int)adr2.type;
	}
	if (adr1.len != adr2.len) {
		return adr1.len < adr2.len;
	}
	return memcmp(adr1.data, adr2.data, adr1.len) < 0;
}

bool operator==(const address &adr1, const address &adr2) {
	return ((adr1.type == adr2.type) &&
			(adr1.len != adr2.len) &&
			memcmp(adr1.data, adr2.data, adr1.len) == 0);
}

struct ConnName {
	address src_addr, dst_addr;
	guint32 src_port, dst_port;
	ConnName(address src_addr, address dst_addr,
			guint32 src_port, guint32 dst_port) :
		src_addr(src_addr), dst_addr(dst_addr), src_port(src_port), dst_port(dst_port) {
	}
	bool operator<(const ConnName &other) const {
		if (src_port!=other.src_port)
			return src_port<other.src_port;
		if (dst_port!=other.dst_port)
			return dst_port<other.dst_port;
		if (!(src_addr==other.src_addr))
			return src_addr<other.src_addr;
		if (!(dst_addr==other.dst_addr))
			return dst_addr<other.dst_addr;
		return false;
	}
};

struct ConnState {
	bool websocket;
	bool replyconn;
	e_guid_t topLevelUUID;
	int connectionnum;
	std::set<int> active_streams;
	ConnState() : websocket(false), replyconn(false), connectionnum(-1) {}
};

typedef std::map<ConnName, ConnState*> ConnMap;

static ConnMap globalState;

static guint32 parse_streamid(tvbuff_t *tvb, gint *offset, gint size) {
    if (size==0) return false;
	guint32 mID;
    unsigned int tempvalue=tvb_get_guint8(tvb, *offset);
    if (tempvalue>=128) {
        if (size<2) return 0;
        tempvalue&=127;
        unsigned int tempvalue1=tvb_get_guint8(tvb, 1 + *offset);
        if (tempvalue1>=128) {
            if (size<4) return 0;
            tempvalue+=(tempvalue1&127)*128;
            tempvalue1=tvb_get_guint8(tvb, 2 + *offset);
            tempvalue+=(tempvalue1*16384);
            tempvalue1=tvb_get_guint8(tvb, 3 + *offset);
            tempvalue+=(tempvalue1*16384*256);
            mID=tempvalue;
			*offset += 4;
        }else {
            size=2;
            mID=tempvalue|(tempvalue1*128);
			*offset += 2;
        }
    }else {
        mID=tempvalue;
		*offset += 1;
    }
    return mID;
}





/*
cdecoder.c - c source to a base64 decoding algorithm implementation

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

typedef enum
{
	step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
	base64_decodestep step;
	char plainchar;
} base64_decodestate;

static
int base64_decode_value(char value_in)
{
	static const char decoding[] = {62,-1,62,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	static const char decoding_size = sizeof(decoding);
	value_in -= 43;
	if (value_in < 0 || value_in > decoding_size) return -1;
	return decoding[(int)value_in];
}

static
void base64_init_decodestate(base64_decodestate* state_in)
{
	state_in->step = step_a;
	state_in->plainchar = 0;
}

static
int base64_decode_block(const char* code_in, const int length_in, char* plaintext_out, base64_decodestate* state_in)
{
	const char* codechar = code_in;
	char* plainchar = plaintext_out;
	char fragment;

	*plainchar = state_in->plainchar;

	switch (state_in->step)
	{
		while (1)
		{
		  case step_a:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_a;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar    = (fragment & 0x03f) << 2;
		  case step_b:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_b;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x030) >> 4;
			*plainchar    = (fragment & 0x00f) << 4;
		  case step_c:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_c;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x03c) >> 2;
			*plainchar    = (fragment & 0x003) << 6;
		  case step_d:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_d;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++   |= (fragment & 0x03f);
		}
	}
	/* control should not reach here */
	return plainchar - plaintext_out;
}


/*          END cdecode.c          */







extern "C"
gboolean heur_dissect_sst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	ConnName thisConnName(pinfo->net_src, pinfo->net_dst, pinfo->srcport, pinfo->destport);
	ConnMap::iterator iter = globalState.find(thisConnName);
	bool ret = false;
	if (iter != globalState.end()) {
		if (iter->second->websocket) {
			ret = process_websocket_packet(tvb, pinfo, tree, 0, 0);
		} else {
			ret = process_tcpsst_packet(tvb, pinfo, tree, 0, 0);
		}
	} else {
        ret = detect_websocket(tvb, pinfo, tree) || detect_tcpsst(tvb, pinfo, tree);
	}
	if (ret) {
		if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SST);
		}
	}
	return ret;
}

static
gboolean process_websocket_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, proto_tree *sst_tree)
{
	proto_item *sst_item = NULL;
	proto_item *sst_sub_item = NULL;
	proto_item *sst_data_item = NULL;
	proto_tree *sst_header_tree = NULL;
	proto_tree *sst_data_tree = NULL;
	gint oldoffset = offset;
	gint length = tvb_length( tvb );
	ConnName thisConnName(pinfo->net_src, pinfo->net_dst, pinfo->srcport, pinfo->destport);
	ConnMap::iterator iter = globalState.find(thisConnName);
	if (iter == globalState.end()) {
		return FALSE;
	}
	ConnState *state = iter->second;
	std::string info;
	{
		char tmpbuf[40];
		char strbuf[15];
		char *mystr = guid_to_str_buf(&state->topLevelUUID, strbuf, 12);
		strbuf[14]='\0';
		sprintf(tmpbuf, "%d -> %d SST [%s]", pinfo->srcport, pinfo->destport, mystr);
		info += tmpbuf;
	}
	if (offset != 0) {
		if (state->replyconn) {
			info += " (WebSocket Response Handshake)";
		} else {
			info += " (WebSocket Request Handshake)";
		}
	}
	if (tree && offset == 0) { /* we are being asked for details */
		proto_item *sst_conn_item = NULL;
		proto_tree *sst_conn_tree = NULL;
		sst_item = proto_tree_add_item(tree, proto_sst, tvb, 0, -1, FALSE);
		sst_tree = proto_item_add_subtree(sst_item, ett_sst);
		sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 0, FALSE);
		sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
		proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 0, 0, state->connectionnum);
		proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 0, 0, &state->topLevelUUID);
	}

	while (offset < length) {
		guint32 pktlen = 0;
		guint32 streamid = -1;
		guint8 pktlenlen = 0;
		guint8 streamidlen = 0;
		bool hasdata = false;
		gint startoffset = offset;
		bool haslength = true;
		if (length-offset > 1) {
			guint8 myint = tvb_get_guint8(tvb, offset);
			++offset;
			if ((myint & 0x80) == 0x80) {
				haslength = true;
				startoffset++;
			} else {
				haslength = false;
			}
		}
		if (haslength && length-offset > 1) {
			oldoffset = offset;
			pktlen = parse_streamid(tvb, &offset, length-offset);
			pktlenlen = (offset - oldoffset);
		} else if (!haslength) {
			oldoffset = offset;
			offset = tvb_find_guint8(tvb, offset, -1, 0xff);
			if (offset == -1) {
				break;
			}
			pktlen = offset-oldoffset;
			pktlenlen = 1;
			offset = oldoffset;
		} else {
			break;
		}
		if (haslength && length-offset > 1) {
			oldoffset = offset;
			streamid = parse_streamid(tvb, &offset, length-offset);
			streamidlen = (offset - oldoffset);
			pktlen -= streamidlen;
		} else {
			gint sidend = tvb_find_guint8(tvb, offset, 8, '%');
			if (length-offset > 1 && sidend != -1) {
				char hexnumber[9]={0};
				streamidlen = (sidend - offset);
				tvb_memcpy(tvb, hexnumber, offset, streamidlen);
				sscanf(hexnumber, "%x", &streamid);
				offset = sidend+1;
				pktlen -= (streamidlen+1);
			} else {
				break;
			}
		}

		if (tree) {
			sst_sub_item = proto_tree_add_item( sst_tree, hf_sst_packet,
					tvb, startoffset, offset+pktlen-startoffset, FALSE );

			sst_header_tree = proto_item_add_subtree(sst_sub_item, ett_sst);

			if (haslength) {
				proto_tree_add_uint(sst_header_tree, hf_sst_length, tvb, startoffset, pktlenlen, pktlen);
			}
			proto_tree_add_uint( sst_header_tree, hf_sst_sid, tvb, startoffset+pktlenlen, streamidlen, streamid );

			if (pktlen > length-offset) {
				pktlen = length-offset;
			}
			sst_data_item = proto_tree_add_item( sst_header_tree, hf_sst_data, tvb, offset, pktlen, FALSE );
			sst_data_tree = proto_item_add_subtree( sst_data_item, ett_sst_data);

			tvbuff_t* tvb_subset;
			if (haslength) {
				tvb_subset = tvb_new_subset(tvb, offset, pktlen, pktlen);
			} else {
				char *base64data = (char*)malloc(pktlen);
				char *base64out = (char*)malloc(pktlen);
				base64_decodestate decodestate;
				base64_init_decodestate(&decodestate);
				tvb_memcpy(tvb, base64data, offset, pktlen);
				gint declen = base64_decode_block(base64data, pktlen, base64out, &decodestate);
				tvb_subset = tvb_new_child_real_data(
					tvb,
					(const guint8 *)base64out,
					declen, declen);
				tvb_set_free_cb(tvb_subset, free);
				//tvb_subset->raw_offset = offset;
				free(base64data);
			}
			parse_protobufs(tvb_subset, pinfo, sst_data_tree);
			//tvb_free(tvb_subset);
			//proto_tree_add_item(sst_header_tree, hf_sst_end, tvb, offset, 0, FALSE);
		}
		{
			char buf[40];
			sprintf(buf, " #%d", streamid);
			info += buf;
		}
		offset += pktlen;

	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", info.c_str());
	}
	return TRUE;
}

static
gboolean detect_websocket(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sst_tree = NULL;
	bool hasheader = false;
	gint offset = 0;
	gint length = tvb_length( tvb );
	ConnName thisConnName(pinfo->net_src, pinfo->net_dst, pinfo->srcport, pinfo->destport);
	ConnMap::iterator iter = globalState.find(thisConnName);
	e_guid_t header_uuid = {0};
	bool isResponseMessage = false;
	if (length >= 95) {
		char header[95];
		tvb_memcpy(tvb, header, 0, 95);
		if (memcmp(header, "GET ", 4)==0) {
			// "GET /" + 36 byte uuid = 41 bytes
			const char *teststr =
				" HTTP/1.1\r\n"
				"Upgrade: WebSocket\r\n"
				"Connection: Upgrade\r\n";
			if (memcmp(header+41, teststr, strlen(teststr))==0) {
				hasheader = true;
			}
		} else {
			const char *teststr =
				"HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
				"Upgrade: WebSocket\r\n"
				"Connection: Upgrade\r\n";
			if (memcmp(header, teststr, strlen(teststr))==0) {
				isResponseMessage = true;
				hasheader = true;
				ConnName otherConnName(pinfo->net_dst, pinfo->net_src, pinfo->destport, pinfo->srcport);
				ConnMap::iterator otherIter = globalState.find(otherConnName);
				if (otherIter != globalState.end()) {
					header_uuid = otherIter->second->topLevelUUID;
				}
			}
		}
	}
	if (hasheader && !isResponseMessage) {
		char uuidstr[37];
		tvb_memcpy(tvb, uuidstr, 5, 36);
		uuidstr[36]='\0';
		GByteArray *gba = g_byte_array_sized_new(16);
		if (!hex_str_to_bytes(uuidstr, gba, false)) {
			hasheader = false;
		} else if (gba->len != 16) {
			hasheader = false;
		}
		if (hasheader) {
			header_uuid.data1 =
				gba->data[0]<<24 |
				gba->data[1]<<16 |
				gba->data[2]<<8 |
				gba->data[3];
			header_uuid.data2 =
				gba->data[4]<<8 |
				gba->data[5];
			header_uuid.data3 =
				gba->data[6]<<8 |
				gba->data[7];
			memcpy(header_uuid.data4, gba->data+8, 8);
		}
		g_byte_array_free(gba, TRUE);
	}
	if (iter == globalState.end() && !hasheader) {
		return FALSE;
	}
	ConnState *state;
	if (iter == globalState.end()) {
		state = new ConnState;
		state->websocket = true;
		state->replyconn = isResponseMessage;
	} else {
		state = iter->second;
	}
	if (tree) { /* we are being asked for details */
		proto_item *sst_item = NULL;
		sst_item = proto_tree_add_item(tree, proto_sst, tvb, 0, -1, FALSE);
		sst_tree = proto_item_add_subtree(sst_item, ett_sst);
	}
	state->topLevelUUID = header_uuid;
	if (hasheader) {
		iter = globalState.insert(ConnMap::value_type(thisConnName, state)).first;
		if (tree) {
			proto_item *sst_conn_item = NULL;
			proto_tree *sst_conn_tree = NULL;
			sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 24, FALSE);
			sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
			proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 6, 2, state->connectionnum);
			proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 8, 16, &state->topLevelUUID);
		}
	}
	if (hasheader) {
		gint tmpoffset = 0;
		while (true) {
			gint next_offset = 0;
			gint linelen = tvb_find_line_end(
				tvb, tmpoffset,
				-1, //tvb_ensure_length_remaining(tvb, tmpoffset),
				&next_offset,
				FALSE);
			if (linelen == -1) {
				hasheader = false;
				break;
			} else if (linelen == 0 || (linelen == 1 && tvb_get_guint8(tvb, tmpoffset)=='\r')) {
				tmpoffset = next_offset;
				break;
			} else {
				tmpoffset = next_offset;
			}
		}
		offset = tmpoffset;
	}
	return process_websocket_packet(tvb, pinfo, tree, offset, sst_tree);
}

static
gboolean process_tcpsst_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset, proto_tree *sst_tree) {
	proto_item *sst_item = NULL;
	proto_item *sst_sub_item = NULL;
	proto_item *sst_data_item = NULL;
	proto_tree *sst_header_tree = NULL;
	proto_tree *sst_data_tree = NULL;
	gint oldoffset = offset;
	gint length = tvb_length( tvb );
	ConnName thisConnName(pinfo->net_src, pinfo->net_dst, pinfo->srcport, pinfo->destport);
	ConnMap::iterator iter = globalState.find(thisConnName);
	if (iter == globalState.end()) {
		return FALSE;
	}
	ConnState *state = iter->second;
	std::string info;
	{
		char tmpbuf[40];
		char strbuf[15];
		char *mystr = guid_to_str_buf(&state->topLevelUUID, strbuf, 12);
		strbuf[14]='\0';
		sprintf(tmpbuf, "%d -> %d SST [%s]", pinfo->srcport, pinfo->destport, mystr);
		info += tmpbuf;
	}
	if (offset != 0) {
		info += " (Handshake)";
	}
	if (tree && offset == 0) { /* we are being asked for details */
		proto_item *sst_conn_item = NULL;
		proto_tree *sst_conn_tree = NULL;
		sst_item = proto_tree_add_item(tree, proto_sst, tvb, 0, -1, FALSE);
		sst_tree = proto_item_add_subtree(sst_item, ett_sst);
		sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 0, FALSE);
		sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
		proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 0, 0, state->connectionnum);
		proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 0, 0, &state->topLevelUUID);
	}

	while (offset < length) {
		guint32 pktlen = 0;
		guint32 streamid = 0;
		guint8 pktlenlen = 0;
		guint8 streamidlen = 0;
		bool hasdata = false;
		gint startoffset = offset;
		if (length-offset > 1) {
			oldoffset = offset;
			pktlen = parse_streamid(tvb, &offset, length-offset);
			pktlenlen = (offset - oldoffset);
			if (length-offset > 1) {
				oldoffset = offset;
				streamid = parse_streamid(tvb, &offset, length-offset);
				streamidlen = (offset - oldoffset);
				pktlen -= streamidlen;
			} else {
				break;
			}
		} else {
			break;
		}

		if (tree) {
			sst_sub_item = proto_tree_add_item( sst_tree, hf_sst_packet,
					tvb, startoffset, offset+pktlen-startoffset, FALSE );

			sst_header_tree = proto_item_add_subtree(sst_sub_item, ett_sst);

			proto_tree_add_uint(sst_header_tree, hf_sst_length, tvb, startoffset, pktlenlen, pktlen);
			proto_tree_add_uint( sst_header_tree, hf_sst_sid, tvb, startoffset+pktlenlen, streamidlen, streamid );

			if (pktlen > length-offset) {
				pktlen = length-offset;
			}
			sst_data_item = proto_tree_add_item( sst_header_tree, hf_sst_data, tvb, offset, pktlen, FALSE );
			sst_data_tree = proto_item_add_subtree( sst_data_item, ett_sst_data);

			tvbuff_t* tvb_subset = tvb_new_subset(tvb, offset, pktlen, pktlen);
			parse_protobufs(tvb_subset, pinfo, sst_data_tree);
//			tvb_free(tvb_subset);
			//proto_tree_add_item(sst_header_tree, hf_sst_end, tvb, offset, 0, FALSE);
		}
		{
			char buf[40];
			sprintf(buf, " #%d", streamid);
			info += buf;
		}
		offset += pktlen;

	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", info.c_str());
	}
	return TRUE;
}

static
gboolean detect_tcpsst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *sst_tree = NULL;
	gint length = tvb_length( tvb );
	gint offset = 0;
	ConnName thisConnName(pinfo->net_src, pinfo->net_dst, pinfo->srcport, pinfo->destport);
	ConnMap::iterator iter = globalState.find(thisConnName);

	bool hasheader = false;
	if (length >= 24) {
		char header[9];
		tvb_memcpy(tvb, header, 0, 8);
		header[8]='\0';
		if (memcmp(header, "SSTTCP", 6)==0) {
			hasheader = true;
		}
	}
	if (iter == globalState.end() && !hasheader) {
		return FALSE;
	}
	ConnState *state;
	if (iter == globalState.end()) {
		state = new ConnState;
	} else {
		state = iter->second;
	}
	if (tree) { /* we are being asked for details */
		proto_item *sst_item = NULL;
		sst_item = proto_tree_add_item(tree, proto_sst, tvb, 0, -1, FALSE);
		sst_tree = proto_item_add_subtree(sst_item, ett_sst);
	}
	if (hasheader) {
		char header[9];
		tvb_memcpy(tvb, header, 0, 8);
		header[8]='\0';

		sscanf(header, "SSTTCP%d", &state->connectionnum);
		tvb_get_guid(tvb, 8, &state->topLevelUUID, FALSE);
		iter = globalState.insert(ConnMap::value_type(thisConnName, state)).first;
		offset = 24;
		if (tree) {
			proto_item *sst_conn_item = NULL;
			proto_tree *sst_conn_tree = NULL;
			sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 24, FALSE);
			sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
			proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 6, 2, state->connectionnum);
			proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 8, 16, &state->topLevelUUID);
		}
	}
	return process_tcpsst_packet(tvb, pinfo, tree, offset, sst_tree);
}

