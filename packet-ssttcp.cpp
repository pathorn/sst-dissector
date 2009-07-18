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
}

#include <string.h>

#define PROTO_TAG_SST "SST"

static int proto_sst = -1;

static dissector_handle_t data_handle=NULL;
static dissector_handle_t sst_handle=NULL;

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
	e_guid_t topLevelUUID;
	int connectionnum;
	std::set<int> active_streams;
	ConnState() : connectionnum(-1) {}
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

extern "C"
gboolean heur_dissect_sst(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *sst_item = NULL;
	proto_item *sst_sub_item = NULL;
	proto_item *sst_conn_item = NULL;
	proto_item *sst_data_item = NULL;
	proto_tree *sst_tree = NULL;
	proto_tree *sst_header_tree = NULL;
	proto_tree *sst_conn_tree = NULL;
	proto_tree *sst_data_tree = NULL;
	gint length = tvb_length( tvb );
	gint offset = 0;
	gint oldoffset = offset;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SST);
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
	}

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
			sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 24, FALSE);
			sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
			proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 6, 2, state->connectionnum);
			proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 8, 16, &state->topLevelUUID);
		}
	} else {
		if (tree) {
			sst_conn_item = proto_tree_add_item(sst_tree, hf_sst_toplevel, tvb, 0, 0, FALSE);
			sst_conn_tree = proto_item_add_subtree(sst_conn_item, ett_sst_toplevel);
			proto_tree_add_uint(sst_conn_tree, hf_sst_connid, tvb, 0, 0, state->connectionnum);
			proto_tree_add_guid(sst_conn_tree, hf_sst_uuid, tvb, 0, 0, &state->topLevelUUID);
		}
	}
	std::string info;
	{
		char tmpbuf[40];
		char strbuf[15];
		char *mystr = guid_to_str_buf(&state->topLevelUUID, strbuf, 12);
		strbuf[14]='\0';
		sprintf(tmpbuf, "%d -> %d SST [%s]", pinfo->srcport, pinfo->destport, mystr);
		info += tmpbuf;
	}
	if (hasheader) {
		info += " (Handshake)";
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
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", info.c_str());
	}
	return TRUE;
}

