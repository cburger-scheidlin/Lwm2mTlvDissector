/* packet-lwm2mtlv.c
 * Routines for LWM2M TLV dissection
 * References:
 *     OMA LWM2M Specification
 *
 * Copyright 2016, Christoph Burger-Scheidlin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

static void dissect_lwm2mtlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void parseArrayOfElements(tvbuff_t *tvb, proto_tree *tlv_tree);
static guint decodeVariableInt(tvbuff_t *tvb, const gint offset, const guint length);

void proto_register_lwm2mtlv(void);

static int proto_lwm2mtlv = -1;

static int hf_lwm2mtlv_header                    = -1;
static int hf_lwm2mtlv_type_type                 = -1;
static int hf_lwm2mtlv_type_length_of_identifier = -1;
static int hf_lwm2mtlv_type_length_of_length     = -1;
static int hf_lwm2mtlv_type_length               = -1;
static int hf_lwm2mtlv_type_ignored              = -1;

static int hf_lwm2mtlv_identifier                = -1;
static int hf_lwm2mtlv_length                    = -1;
static int hf_lwm2mtlv_value                     = -1;
static int hf_lwm2mtlv_value_string              = -1;
static int hf_lwm2mtlv_value_integer             = -1;
static int hf_lwm2mtlv_value_float               = -1;
static int hf_lwm2mtlv_value_double              = -1;
static int hf_lwm2mtlv_value_boolean             = -1;
static int hf_lwm2mtlv_value_timestamp           = -1;

static int hf_lwm2mtlv_resource                  = -1;
static int hf_lwm2mtlv_resourceInstance          = -1;
static int hf_lwm2mtlv_resourceArray             = -1;
static int hf_lwm2mtlv_objectInstance            = -1;

static gint ett_lwm2mtlv        = -1;
static gint ett_lwm2mtlv_entry  = -1;
static gint ett_lwm2mtlv_header = -1;
static gint ett_lwm2mtlv_value  = -1;


typedef enum {
	OBJECT_INSTANCE   = 0,
	RESOURCE_INSTANCE = 1,
	RESOURCE_ARRAY    = 2,
	RESOURCE          = 3
} lwm2m_identifier_t;

static const value_string identifiers[] = {
	{ OBJECT_INSTANCE,   "Object Instance" },
	{ RESOURCE_INSTANCE, "Resource Instance" },
	{ RESOURCE_ARRAY,    "Multiple Resources" },
	{ RESOURCE,          "Resource with value" },
	{ 0, NULL }
};

static const value_string length_identifier[] = {
	{ 0x00, "1 byte identifier" },
	{ 0x01, "2 bytes identifier" },
	{ 0, NULL }
};

static const value_string length_type[] = {
	{ 0x00, "No length field" },
	{ 0x01, "1 byte length field" },
	{ 0x02, "2 bytes length field" },
	{ 0x03, "3 bytes length field" },
	{ 0, NULL }
};

typedef struct
{
	guint type;
	guint length_of_identifier;
	guint length_of_length;
	guint length_of_value;
	guint identifier;
	guint length;
	guint totalLength;
} lwm2mElement_t;

void proto_register_lwm2mtlv(void)
{
	static hf_register_info hf[] = {
		{ &hf_lwm2mtlv_header,
			"TLV header", "tlv.header",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_type_type,
			"Type of Identifier", "tlv.type.type",
			FT_UINT8, BASE_DEC, VALS(identifiers), 0xC0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_type_length_of_identifier,
			"Length of Identifier", "tlv.type.loi",
			FT_UINT8, BASE_DEC, VALS(length_identifier), 0x20,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_type_length_of_length,
			"Length of Length", "tlv.type.lol",
			FT_UINT8, BASE_DEC, VALS(length_type), 0x18,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_type_length,
			"Length", "tlv.type.length",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_type_ignored,
			"Ignored", "tlv.type.ignored",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_identifier,
			"Identifier", "tlv.identifier",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_length,
			"Length", "tlv.length",
			FT_UINT32, BASE_DEC, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value,
			"Value", "tlv.value",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_string,
			"As String", "tlv.value.string",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_integer,
			"As Integer", "tlv.value.integer",
			FT_INT64, BASE_DEC, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_float,
			"As Float", "tlv.value.float",
			FT_FLOAT, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_double,
			"As Double", "tlv.value.double",
			FT_DOUBLE, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_boolean,
			"As Boolean", "tlv.value.boolean",
			FT_BOOLEAN, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_value_timestamp,
			"As Timestamp", "tlv.value.timestamp",
			FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_resource,
			"Resource", "tlv.resource",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_resourceInstance,
			"Entry", "tlv.resourceInstance",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_resourceArray,
			"Array", "tlv.resourceArray",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
		{ &hf_lwm2mtlv_objectInstance,
			"Object Instance", "tlv.resource",
			FT_STRING, BASE_NONE, NULL, 0,
			NULL, HFILL
		},
	};

	static gint* ett[] = {
		&ett_lwm2mtlv,
		&ett_lwm2mtlv_entry,
		&ett_lwm2mtlv_header,
		&ett_lwm2mtlv_value
	};

	/* Register our configuration options */
	proto_lwm2mtlv = proto_register_protocol (
        "Lightweight M2M TLV",
        "LwM2M-TLV",
        "lwm2mtlv"
        );

	proto_register_field_array(proto_lwm2mtlv, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("lwm2mtlv", dissect_lwm2mtlv, proto_lwm2mtlv);
}

void
proto_reg_handoff_lwm2mtlv(void)
{
    static dissector_handle_t lwm2mtlv_handle;

    lwm2mtlv_handle = create_dissector_handle(dissect_lwm2mtlv, proto_lwm2mtlv);
    dissector_add_string("media_type", "Unknown Type 1542", lwm2mtlv_handle);
}

static void
addTlvHeaderElements(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length_of_identifier, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length_of_length, tvb, 0, 1, ENC_BIG_ENDIAN);
	if ( element->length_of_length == 0 )
	{
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length, tvb, 0, 1, ENC_BIG_ENDIAN);
	}
	else
	{
		proto_item *item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_ignored, tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_item_set_text(item, "TLV header");
	}

	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_identifier, tvb, 1, element->length_of_identifier, ENC_BIG_ENDIAN);

	if ( element->length_of_length > 0 )
	{
		/* TODO need to decode better here (multiple bytes) */
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_length, tvb, 1+element->length_of_identifier, element->length_of_length, ENC_BIG_ENDIAN);
	}
}

static void
addTlvHeaderTree(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_item *item = NULL;
	proto_tree *header_tree = NULL;

	guint valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_header, tvb, 0, valueOffset, ENC_BIG_ENDIAN);
	proto_item_set_text(item, "TLV header");
	header_tree = proto_item_add_subtree(item, ett_lwm2mtlv_header);
	addTlvHeaderElements(tvb, header_tree, element);
}

static proto_tree*
addElementTree(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_item *item = NULL;
	guint valueOffset = 1 + element->length_of_identifier + element->length_of_length;
	char *str;

	switch ( element->type )
	{
	case OBJECT_INSTANCE:
		item = proto_tree_add_string_format(tlv_tree, hf_lwm2mtlv_objectInstance, tvb, 0, element->totalLength, "no idea", "Object Instance %02u (%u Bytes)", element->identifier, element->length_of_value);
		break;

	case RESOURCE_INSTANCE:
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, valueOffset, element->length_of_value, ENC_ASCII);
		item = proto_tree_add_string_format(tlv_tree, hf_lwm2mtlv_resourceInstance, tvb, 0, element->totalLength, "%u: %s", "%02u: %s", element->identifier, str);
		break;

	case RESOURCE_ARRAY:
		item = proto_tree_add_string_format(tlv_tree, hf_lwm2mtlv_resourceArray, tvb, 0, element->totalLength, "no idea", "%02u: (Array of %u Bytes)", element->identifier, element->length_of_value);
		break;

	case RESOURCE:
		str = tvb_get_string_enc(wmem_packet_scope(), tvb, valueOffset, element->length_of_value, ENC_ASCII);
		item = proto_tree_add_string_format(tlv_tree, hf_lwm2mtlv_resource, tvb, 0, element->totalLength, "no idea", "%02u: %s", element->identifier, str);
		break;
	}

	return proto_item_add_subtree(item, ett_lwm2mtlv_entry);
}

static inline void
addString(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_string, tvb, offset, length, ENC_BIG_ENDIAN);
}

static inline void
addInteger(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_integer, tvb, offset, length, ENC_BIG_ENDIAN);
}

static inline void
addFloat(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_float, tvb, offset, length, ENC_BIG_ENDIAN);
}

static inline void
addDouble(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_double, tvb, offset, length, ENC_BIG_ENDIAN);
}

static inline void
addBoolean(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_boolean, tvb, offset, length, ENC_BIG_ENDIAN);
}

static inline void
addTimestamp(tvbuff_t *tvb, proto_tree *tlv_tree, guint offset, guint length)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_timestamp, tvb, offset, length, ENC_BIG_ENDIAN);
}

static void
addValueInterpretations(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	if ( element->length_of_value == 0 ) return;

	guint valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	addString(tvb, tlv_tree, valueOffset, element->length_of_value);

	switch(element->length_of_value)
	{
	case 0x01:
		addInteger(tvb, tlv_tree, valueOffset, element->length_of_value);
		addBoolean(tvb, tlv_tree, valueOffset, element->length_of_value);
		break;
	case 0x02:
		addInteger(tvb, tlv_tree, valueOffset, element->length_of_value);
		break;
	case 0x04:
		addInteger(tvb, tlv_tree, valueOffset, element->length_of_value);
		addFloat(tvb, tlv_tree, valueOffset, element->length_of_value);
		addTimestamp(tvb, tlv_tree, valueOffset, element->length_of_value);
		break;
	case 0x08:
		addInteger(tvb, tlv_tree, valueOffset, element->length_of_value);
		addDouble(tvb, tlv_tree, valueOffset, element->length_of_value);
		/* apparently, wireshark does not deal well with 8 bytes. */
		addTimestamp(tvb, tlv_tree, valueOffset+4, element->length_of_value-4);
		break;
	}
}

static void
addValueTree(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	guint valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	if ( element->type == RESOURCE || element->type == RESOURCE_INSTANCE ) {
		proto_item *item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
		proto_tree *value_tree = proto_item_add_subtree(item, ett_lwm2mtlv_value);
		addValueInterpretations(tvb, value_tree, element);
	} else {
		tvbuff_t* sub = tvb_new_subset_length(tvb, valueOffset, element->length_of_value);
		parseArrayOfElements(sub, tlv_tree);
	}
}

static void
addTlvElement(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_tree *element_tree = NULL;

	element_tree = addElementTree(tvb, tlv_tree, element);
	addTlvHeaderTree(tvb, element_tree, element);
	addValueTree(tvb, element_tree, element);
}

static guint
decodeVariableInt(tvbuff_t *tvb, const gint offset, const guint length)
{
	switch(length)
	{
	case 1:
		return tvb_get_guint8(tvb, offset);
	case 2:
		return tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	case 3:
		return tvb_get_guint24(tvb, offset, ENC_LITTLE_ENDIAN);
	case 4:
		return tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
	case 5:
		return tvb_get_guint40(tvb, offset, ENC_LITTLE_ENDIAN);
	case 6:
		return tvb_get_guint48(tvb, offset, ENC_LITTLE_ENDIAN);
	case 7:
		return tvb_get_guint56(tvb, offset, ENC_LITTLE_ENDIAN);
	case 8:
		return tvb_get_guint64(tvb, offset, ENC_LITTLE_ENDIAN);
	default:
		return 0;
	}
}

static guint parseTLVHeader(tvbuff_t *tvb, lwm2mElement_t *element)
{
	guint type_field = tvb_get_guint8(tvb, 0);
	element->type                 = (( type_field >> 6 ) & 0x03 );
	element->length_of_identifier = (( type_field >> 5 ) & 0x01 ) + 1;
	element->length_of_length     = (( type_field >> 3 ) & 0x03 );
	element->length_of_value      = (( type_field >> 0 ) & 0x07 );

	element->identifier = decodeVariableInt(tvb, 1, element->length_of_identifier);
	if ( element->length_of_length > 0 ) {
		element->length_of_value = decodeVariableInt(tvb, 1 + element->length_of_identifier, element->length_of_length);
	}

	element->totalLength = 1 + element->length_of_identifier + element->length_of_length + element->length_of_value;
	return element->totalLength;
}

static void parseArrayOfElements(tvbuff_t *tvb, proto_tree *tlv_tree)
{
	guint length;
	guint offset = 0;
	guint elementLength = 0;
	lwm2mElement_t element;

	length = tvb_reported_length(tvb);

	while ( length > 0 ) {
		tvbuff_t* sub = tvb_new_subset_length(tvb, offset, length);
		elementLength = parseTLVHeader(sub, &element);
		addTlvElement(sub, tlv_tree, &element);

		length -= elementLength;
		offset += elementLength;
		if ( elementLength == 0 )
		{
			break;
		}
	}
}

static void dissect_lwm2mtlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (tree) { /* we are being asked for details */
		proto_item *tlv = NULL;
		proto_tree *tlv_tree = NULL;

		proto_item* parent = proto_tree_get_parent(tree);
		proto_item_set_text(parent, "Payload: Lightweight M2M TLV Format, Length: %u", tvb_reported_length(tvb));
		proto_item_set_text(parent->first_child, "Payload Desc: Lightweight M2M TLV Format");

		parseArrayOfElements(tvb, tree);
	}
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
