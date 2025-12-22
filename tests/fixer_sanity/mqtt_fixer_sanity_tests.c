/* Auto-generated MQTT fixer sanity tests.
 * Generated from mqtt_fixers.c function list.
 * Place this file under: tests/fixer_sanity/mqtt_fixer_sanity_tests.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


/* IMPORTANT: we include the fixer implementation directly so static helpers/vars are visible. */

#include "../../llm/mqtt/mqtt_fixers.c"


/* Property Identifiers (MQTT v5) used by oracles in this test file. */

#define T_PROP_ID_PFI 0x01u

#define T_PROP_ID_MEI 0x02u

#define T_PROP_ID_CONTENT_TYPE 0x03u

#define T_PROP_ID_RESPONSE_TOPIC 0x08u

#define T_PROP_ID_CORR_DATA 0x09u

#define T_PROP_ID_SUB_ID 0x0Bu

#define T_PROP_ID_TOPIC_ALIAS 0x23u

#define T_PROP_ID_USER_PROP 0x26u


/* CONNECT Flags bit layout (MQTT v3.1.1/v5) */
#define MQTT_CF_USERNAME       (1u<<7)
#define MQTT_CF_PASSWORD       (1u<<6)
#define MQTT_CF_WILL_RETAIN    (1u<<5)
#define MQTT_CF_WILL_QOS_MASK  (0x03u<<3)
#define MQTT_CF_WILL           (1u<<2)
#define MQTT_CF_CLEAN_START    (1u<<1)

static inline void mqtt_set_bit(uint8_t *flags, uint8_t mask, int v) {
  if (!flags) return;
  if (v) *flags |= mask;
  else   *flags &= (uint8_t)~mask;
}
static inline int mqtt_get_bit(uint8_t flags, uint8_t mask) {
  return (flags & mask) ? 1 : 0;
}
static inline void mqtt_set_will_qos(uint8_t *flags, uint8_t qos) {
  if (!flags) return;
  *flags = (uint8_t)((*flags & (uint8_t)~MQTT_CF_WILL_QOS_MASK) | ((qos & 0x03u) << 3));
}
static inline uint8_t mqtt_get_will_qos(uint8_t flags) {
  return (uint8_t)((flags & MQTT_CF_WILL_QOS_MASK) >> 3);
}



static int g_failures = 0;


#define T_ASSERT(cond) do { if (!(cond)) return 1; } while (0)

#define T_ASSERT_MSG(cond, msg) do { if (!(cond)) { fprintf(stderr, "    [FAIL] %s\n", msg); return 1; } } while (0)


static int has_wildcard(const char *s) {
  if (!s) return 0;
  for (const char *p = s; *p; ++p) { if (*p == '+' || *p == '#') return 1; }
  return 0;
}


static int is_ascii_printable(const char *s) {
  if (!s) return 1;
  for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
    if (*p >= 0x80) return 0;
  }
  return 1;
}


static size_t enc_varint(uint32_t v, uint8_t *out, size_t cap) {
  size_t n = 0;
  do {
    if (n >= cap) return 0;
    uint8_t b = (uint8_t)(v % 128u);
    v /= 128u;
    if (v > 0) b |= 0x80u;
    out[n++] = b;
  } while (v > 0);
  return n;
}


static int props_count_id(const uint8_t *p, uint32_t len, uint8_t id) {
  /* Count by parsing property framing (avoid counting bytes inside lengths/payload). */
  if (!p || len == 0) return 0;

  uint32_t i = 0;
  int count = 0;

  while (i < len) {
    uint8_t pid = p[i++];

    if (pid == id) count++;

    if (pid == T_PROP_ID_RESPONSE_TOPIC || pid == T_PROP_ID_CONTENT_TYPE || pid == T_PROP_ID_CORR_DATA) {
      if (i + 2 > len) break;
      uint16_t n = (uint16_t)((p[i] << 8) | p[i+1]);
      i += 2;
      if (i + (uint32_t)n > len) break;
      i += (uint32_t)n;
    } else if (pid == T_PROP_ID_TOPIC_ALIAS) {
      if (i + 2 > len) break;
      i += 2;
    } else if (pid == T_PROP_ID_PFI) {
      if (i + 1 > len) break;
      i += 1;
    } else if (pid == T_PROP_ID_MEI) {
      if (i + 4 > len) break;
      i += 4;
    } else if (pid == T_PROP_ID_USER_PROP) {
      if (i + 2 > len) break;
      uint16_t k = (uint16_t)((p[i] << 8) | p[i+1]);
      i += 2;
      if (i + (uint32_t)k > len) break;
      i += (uint32_t)k;

      if (i + 2 > len) break;
      uint16_t v = (uint16_t)((p[i] << 8) | p[i+1]);
      i += 2;
      if (i + (uint32_t)v > len) break;
      i += (uint32_t)v;
    } else if (pid == T_PROP_ID_SUB_ID) {
      /* Subscription Identifier: Variable Byte Integer */
      uint32_t value = 0;
      uint32_t mul = 1;
      int cnt = 0;
      while (i < len) {
        uint8_t b = p[i++];
        value += (uint32_t)(b & 0x7Fu) * mul;
        cnt++;
        if ((b & 0x80u) == 0) break;
        mul *= 128u;
        if (cnt >= 4) break; /* malformed, stop */
      }
      (void)value;
    } else {
      /* Unknown property id in this suite -> stop to avoid OOB / false positives. */
      break;
    }
  }
  return count;
}



static int props_get_first_response_topic(const uint8_t *p, uint32_t len, char *out, size_t out_cap) {
  if (!p || !out || out_cap == 0) return 0;
  uint32_t i = 0;
  while (i < len) {
    uint8_t id = p[i++];
    if (id == T_PROP_ID_RESPONSE_TOPIC || id == T_PROP_ID_CONTENT_TYPE || id == T_PROP_ID_CORR_DATA) {
      if (i + 2 > len) return 0;
      uint16_t slen = (uint16_t)((p[i] << 8) | p[i+1]);
      i += 2;
      if (i + slen > len) return 0;
      if (id == T_PROP_ID_RESPONSE_TOPIC) {
        size_t cpy = slen;
        if (cpy >= out_cap) cpy = out_cap - 1;
        memcpy(out, &p[i], cpy);
        out[cpy] = '\0';
        return 1;
      }
      i += slen;
    } else if (id == T_PROP_ID_TOPIC_ALIAS) {
      if (i + 2 > len) return 0;
      i += 2;
    } else if (id == T_PROP_ID_PFI) {
      if (i + 1 > len) return 0;
      i += 1;
    } else if (id == T_PROP_ID_MEI) {
      if (i + 4 > len) return 0;
      i += 4;
    } else if (id == T_PROP_ID_SUB_ID) {
      /* skip varint */
      int guard = 0;
      while (i < len) {
        uint8_t b = p[i++];
        guard++;
        if ((b & 0x80u) == 0) break;
        if (guard > 4) return 0;
      }
    } else if (id == T_PROP_ID_USER_PROP) {
      /* key */
      if (i + 2 > len) return 0;
      uint16_t klen = (uint16_t)((p[i] << 8) | p[i+1]); i += 2;
      if (i + klen > len) return 0; i += klen;
      /* val */
      if (i + 2 > len) return 0;
      uint16_t vlen = (uint16_t)((p[i] << 8) | p[i+1]); i += 2;
      if (i + vlen > len) return 0; i += vlen;
    } else {
      /* unknown id -> stop (our tests should not generate unknowns) */
      return 0;
    }
  }
  return 0;
}


static int props_has_sub_id(const uint8_t *p, uint32_t len) {
  for (uint32_t i = 0; i < len; ++i) { if (p[i] == T_PROP_ID_SUB_ID) return 1; }
  return 0;
}


static int props_get_topic_alias_u16(const uint8_t *p, uint32_t len, uint16_t *out_alias) {
  if (!p || !out_alias) return 0;
  for (uint32_t i = 0; i + 3 <= len; ++i) {
    if (p[i] == T_PROP_ID_TOPIC_ALIAS) {
      *out_alias = (uint16_t)((p[i+1] << 8) | p[i+2]);
      return 1;
    }
  }
  return 0;
}


static void zero_bytes(void *p, size_t n) { memset(p, 0, n); }


static int test_fix_connect_protocol_name_mqtt(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
/* make it obviously wrong */
snprintf(p.variable_header.protocol_name, sizeof(p.variable_header.protocol_name), "BAD");
p.variable_header.protocol_level = 5;
fix_connect_protocol_name_mqtt(&p, 1);
T_ASSERT_MSG(strcmp(p.variable_header.protocol_name, "MQTT") == 0, "protocol_name should be fixed to MQTT");
return 0;
}


static int test_fix_user_name_flag(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_USERNAME, 0);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_PASSWORD, 1);
snprintf(p.payload.user_name, sizeof(p.payload.user_name), "u");
p.payload.password_len = 1;
p.payload.password[0] = 'p';
fix_user_name_flag(&p, 1);
T_ASSERT_MSG( mqtt_get_bit(p.variable_header.connect_flags, MQTT_CF_USERNAME) == 0, "user_name_flag should remain 0");
T_ASSERT_MSG(p.payload.user_name[0] == '\0', "user_name must be cleared when user_name_flag=0");
T_ASSERT_MSG( mqtt_get_bit(p.variable_header.connect_flags, MQTT_CF_PASSWORD) == 0, "password_flag must be cleared when user_name_flag=0");
T_ASSERT_MSG(p.payload.password_len == 0, "password_len must be cleared when user_name_flag=0");
T_ASSERT_MSG(p.payload.password[0] == '\0', "password must be cleared when user_name_flag=0");

/* now require a username when flag is 1 */
memset(&p, 0, sizeof(p));
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_USERNAME, 1);
p.payload.user_name[0] = '\0';
fix_user_name_flag(&p, 1);
T_ASSERT_MSG(p.payload.user_name[0] != '\0', "user_name must be populated when user_name_flag=1");
return 0;
}


static int test_fix_password_flag(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_PASSWORD, 0);
p.payload.password_len = 3;
p.payload.password[0] = 'x';
fix_password_flag(&p, 1);
T_ASSERT_MSG(p.payload.password_len == 0, "password_len must be cleared when password_flag=0");
T_ASSERT_MSG(p.payload.password[0] == '\0', "password must be cleared when password_flag=0");

memset(&p, 0, sizeof(p));
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_PASSWORD, 1);
p.payload.password_len = 0;
p.payload.password[0] = '\0';
fix_password_flag(&p, 1);
T_ASSERT_MSG(p.payload.password_len > 0, "password_len must be set when password_flag=1");
return 0;
}


static int test_fix_connect_packet_will_rules(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.protocol_level = 5;
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL, 0);
mqtt_set_will_qos(&p.variable_header.connect_flags, (uint8_t)3); /* invalid */
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL_RETAIN, 1);
snprintf(p.payload.will_topic, sizeof(p.payload.will_topic), "t");
p.payload.will_payload_len = 2;
p.payload.will_payload[0] = 'A';
p.payload.will_payload[1] = 'B';
p.payload.will_property_len = 2;
p.payload.will_properties[0] = 0x01;
p.payload.will_properties[1] = 0x00;
fix_connect_packet_will_rules(&p, 1);
T_ASSERT_MSG(p.payload.will_topic[0] == '\0', "will_topic cleared when will_flag=0");
T_ASSERT_MSG(p.payload.will_payload_len == 0, "will_payload_len cleared when will_flag=0");
T_ASSERT_MSG(p.payload.will_property_len == 0, "will_property_len cleared when will_flag=0");
T_ASSERT_MSG( mqtt_get_will_qos(p.variable_header.connect_flags) == 0, "will_qos cleared when will_flag=0");
T_ASSERT_MSG( mqtt_get_bit(p.variable_header.connect_flags, MQTT_CF_WILL_RETAIN) == 0, "will_retain cleared when will_flag=0");

/* protocol_level <5: will properties must be removed */
memset(&p, 0, sizeof(p));
p.variable_header.protocol_level = 4;
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL, 1);
p.payload.will_property_len = 5;
p.payload.will_properties[0] = 0x99;
fix_connect_packet_will_rules(&p, 1);
T_ASSERT_MSG(p.payload.will_property_len == 0, "will_property_len must be 0 for MQTT <5");

/* will_flag=1: ensure will_topic/payload/properties present and will_qos valid */
memset(&p, 0, sizeof(p));
p.variable_header.protocol_level = 5;
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL, 1);
mqtt_set_will_qos(&p.variable_header.connect_flags, (uint8_t)3); /* invalid */
p.payload.will_topic[0] = '\0';
p.payload.will_payload_len = 0;
p.payload.will_property_len = 0;
fix_connect_packet_will_rules(&p, 1);
T_ASSERT_MSG( mqtt_get_will_qos(p.variable_header.connect_flags) <= 2, "will_qos must be in [0,2]");
T_ASSERT_MSG(p.payload.will_topic[0] != '\0', "will_topic must be set when will_flag=1");
T_ASSERT_MSG(p.payload.will_payload_len > 0, "will_payload_len must be set when will_flag=1");
T_ASSERT_MSG(p.payload.will_property_len == 2, "will_property_len must be initialized for MQTT5 when missing");
T_ASSERT_MSG(p.payload.will_properties[0] == 0x01 && p.payload.will_properties[1] == 0x00, "default will properties must be present");
return 0;
}


static int test_fix_connect_all_length(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.protocol_name, sizeof(p.variable_header.protocol_name), "MQTT");
p.variable_header.protocol_level = 5;
p.variable_header.keep_alive = 60;
p.variable_header.property_len = 0;

/* flags */
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_USERNAME, 1);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_PASSWORD, 1);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL, 1);
mqtt_set_will_qos(&p.variable_header.connect_flags, (uint8_t)1);

snprintf(p.payload.client_id, sizeof(p.payload.client_id), "cid");
snprintf(p.payload.user_name, sizeof(p.payload.user_name), "uname");

/* set password bytes but leave password_len wrong */
p.payload.password_len = 0;
p.payload.password[0] = 'p';
p.payload.password[1] = 'w';

/* set will payload bytes but leave len wrong */
snprintf(p.payload.will_topic, sizeof(p.payload.will_topic), "wt");
p.payload.will_payload_len = 0;
p.payload.will_payload[0] = 'X';
p.payload.will_payload[1] = 'Y';

/* set will properties but leave len wrong */
p.payload.will_property_len = 0;
p.payload.will_properties[0] = 0x01;
p.payload.will_properties[1] = 0x00;

fix_connect_all_length(&p, 1);

T_ASSERT_MSG(p.payload.password_len == 2, "password_len should be derived from last non-zero byte");
T_ASSERT_MSG(p.payload.will_payload_len == 2, "will_payload_len should be derived from last non-zero byte");
T_ASSERT_MSG(p.payload.will_property_len == 2, "will_property_len should be derived from last non-zero byte");

/* check remaining_length formula (must match fixer logic) */
size_t vh_len = 0;
vh_len += 2 + strlen(p.variable_header.protocol_name);
vh_len += 1; /* protocol_level */
vh_len += 1; /* connect_flags */
vh_len += 2; /* keep_alive */
vh_len += p.variable_header.property_len;

size_t pl_len = 0;
pl_len += 2 + strlen(p.payload.client_id);
/* will section */
pl_len += p.payload.will_property_len;
pl_len += 2 + strlen(p.payload.will_topic);
pl_len += 2 + p.payload.will_payload_len;
/* username/password */
pl_len += 2 + strlen(p.payload.user_name);
pl_len += 2 + p.payload.password_len;

size_t expected = vh_len + pl_len;
T_ASSERT_MSG(p.fixed_header.remaining_length == expected, "connect remaining_length must match computed size");
return 0;
}


static int test_fix_connect(void) {
mqtt_connect_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.protocol_name, sizeof(p.variable_header.protocol_name), "BAD");
p.variable_header.protocol_level = 5;
p.variable_header.keep_alive = 10;

/* conflicting flags */
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_USERNAME, 1);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_PASSWORD, 1);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL, 0);
mqtt_set_will_qos(&p.variable_header.connect_flags, (uint8_t)3);
mqtt_set_bit(&p.variable_header.connect_flags, MQTT_CF_WILL_RETAIN, 1);

snprintf(p.payload.client_id, sizeof(p.payload.client_id), "cid");
p.payload.user_name[0] = '\0';
p.payload.password_len = 1;
p.payload.password[0] = 'p';

snprintf(p.payload.will_topic, sizeof(p.payload.will_topic), "should_clear");
p.payload.will_payload_len = 1;
p.payload.will_payload[0] = 'x';

fix_connect(&p, 1);

T_ASSERT_MSG(strcmp(p.variable_header.protocol_name, "MQTT") == 0, "protocol_name fixed");
T_ASSERT_MSG(p.payload.user_name[0] != '\0', "username must be present if flag set");
T_ASSERT_MSG(p.payload.will_topic[0] == '\0' && p.payload.will_payload_len == 0, "will fields cleared when will_flag=0");
return 0;
}


static int test_fix_subscribe_reserved_flags(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_SUBSCRIBE << 4) | 0x0Fu);
fix_subscribe_reserved_flags(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "SUBSCRIBE reserved flags must be 0x2");
return 0;
}


static int test_fix_subscribe_topic_filters_utf8(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 1;
/* create a non-ascii and non-NUL-terminated filter */
memset(p.payload.topic_filters[0].topic_filter, 0xFF, sizeof(p.payload.topic_filters[0].topic_filter));
p.payload.topic_filters[0].topic_filter[0] = 'a';
p.payload.topic_filters[0].topic_filter[1] = '/';
p.payload.topic_filters[0].qos = 0;
fix_subscribe_topic_filters_utf8(&p, 1);
T_ASSERT_MSG(p.payload.topic_filters[0].topic_filter[MAX_TOPIC_LEN-1] == '\0', "topic_filter must be NUL terminated");
T_ASSERT_MSG(p.payload.topic_filters[0].topic_filter[0] != '\0', "topic_filter must be non-empty");
T_ASSERT_MSG(is_ascii_printable(p.payload.topic_filters[0].topic_filter), "topic_filter must be ASCII after sanitization");
return 0;
}


static int test_fix_subscribe_payload_has_topic_pair(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 0;
fix_subscribe_payload_has_topic_pair(&p, 1);
T_ASSERT_MSG(p.payload.topic_count == 1, "topic_count must be at least 1");
T_ASSERT_MSG(strcmp(p.payload.topic_filters[0].topic_filter, "fixed/topic") == 0, "default topic_filter should be inserted");
T_ASSERT_MSG(p.payload.topic_filters[0].qos == 0, "default qos should be 0");

memset(&p, 0, sizeof(p));
p.payload.topic_count = (uint8_t)(MAX_TOPIC_FILTERS + 10);
fix_subscribe_payload_has_topic_pair(&p, 1);
T_ASSERT_MSG(p.payload.topic_count == MAX_TOPIC_FILTERS, "topic_count must be clamped to MAX_TOPIC_FILTERS");
return 0;
}


static int test_fix_subscribe_shared_subscription_filters(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 1;
snprintf(p.payload.topic_filters[0].topic_filter, sizeof(p.payload.topic_filters[0].topic_filter), "$share");
fix_subscribe_shared_subscription_filters(&p, 1);
T_ASSERT_MSG(strcmp(p.payload.topic_filters[0].topic_filter, "$share/group/topic") == 0, "shared subscription filter must be expanded");
return 0;
}


static int test_fix_subscribe_no_local(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 1;
snprintf(p.payload.topic_filters[0].topic_filter, sizeof(p.payload.topic_filters[0].topic_filter), "t");
p.payload.topic_filters[0].qos = 0x04u; /* no_local bit set */
fix_subscribe_no_local(&p, 1);
T_ASSERT_MSG((p.payload.topic_filters[0].qos & 0x04u) == 0, "no_local bit must be cleared");
return 0;
}


static int test_fix_subscribe_packet_identifier(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 0;
fix_subscribe_packet_identifier(&p, 1);
T_ASSERT_MSG(p.variable_header.packet_identifier != 0, "packet_identifier must be non-zero");
return 0;
}


static int test_fix_subscribe_packet_identifier_unique(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 123;
/* packet_id_used is a static from mqtt_fixers.c, visible because we included it */
memset(packet_id_used, 0, sizeof(packet_id_used));
packet_id_used[123] = 1;
fix_subscribe_packet_identifier_unique(&p, 1);
T_ASSERT_MSG(p.variable_header.packet_identifier != 0, "unique packet_identifier must be non-zero");
T_ASSERT_MSG(p.variable_header.packet_identifier != 123, "unique packet_identifier must change if already used");
return 0;
}


static int test_fix_subscribe_all_length(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 7;
p.variable_header.property_len = 0;
p.payload.topic_count = 2;
snprintf(p.payload.topic_filters[0].topic_filter, sizeof(p.payload.topic_filters[0].topic_filter), "a/b");
p.payload.topic_filters[0].qos = 1;
snprintf(p.payload.topic_filters[1].topic_filter, sizeof(p.payload.topic_filters[1].topic_filter), "c");
p.payload.topic_filters[1].qos = 0;
fix_subscribe_all_length(&p, 1);

size_t payload_len = 0;
payload_len += 2 + strlen("a/b") + 1;
payload_len += 2 + strlen("c") + 1;
size_t vh_len = 2 + p.variable_header.property_len;
size_t expected = vh_len + payload_len;
T_ASSERT_MSG(p.fixed_header.remaining_length == expected, "subscribe remaining_length must match computed size");
return 0;
}


static int test_fix_subscribe(void) {
mqtt_subscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_SUBSCRIBE << 4) | 0x00u);
p.variable_header.packet_identifier = 0;
p.payload.topic_count = 0;
fix_subscribe(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "subscribe wrapper should fix reserved flags");
T_ASSERT_MSG(p.variable_header.packet_identifier != 0, "subscribe wrapper should set packet_identifier");
T_ASSERT_MSG(p.payload.topic_count >= 1, "subscribe wrapper should ensure topic_count >= 1");
return 0;
}


static int test_fix_sub_unsub_topic_filters_length_and_nul(void) {
mqtt_subscribe_packet_t sub;
mqtt_unsubscribe_packet_t unsub;
memset(&sub, 0, sizeof(sub));
memset(&unsub, 0, sizeof(unsub));

sub.payload.topic_count = 1;
memset(sub.payload.topic_filters[0].topic_filter, 'A', sizeof(sub.payload.topic_filters[0].topic_filter));
sub.payload.topic_filters[0].topic_filter[sizeof(sub.payload.topic_filters[0].topic_filter)-1] = 'B'; /* ensure no NUL */
sub.payload.topic_filters[0].qos = 0;

unsub.payload.topic_count = 1;
memset(unsub.payload.topic_filters[0], 'C', sizeof(unsub.payload.topic_filters[0]));
unsub.payload.topic_filters[0][sizeof(unsub.payload.topic_filters[0])-1] = 'D'; /* ensure no NUL */

fix_sub_unsub_topic_filters_length_and_nul(&sub, 1, &unsub, 1);

T_ASSERT_MSG(sub.payload.topic_filters[0].topic_filter[MAX_TOPIC_LEN-1] == '\0', "subscribe topic_filter must be NUL terminated");
T_ASSERT_MSG(unsub.payload.topic_filters[0][MAX_TOPIC_LEN-1] == '\0', "unsubscribe topic_filter must be NUL terminated");
return 0;
}


static int test_fix_unsubscribe_payload_has_topic_filter(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 0;
fix_unsubscribe_payload_has_topic_filter(&p, 1);
T_ASSERT_MSG(p.payload.topic_count == 1, "unsubscribe topic_count must be at least 1");
T_ASSERT_MSG(strcmp(p.payload.topic_filters[0], "fixed/topic") == 0, "default topic_filter inserted");
return 0;
}


static int test_fix_unsubscribe_payload_has_topic_filter_mqtt_3_10_3_2(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 0;
fix_unsubscribe_payload_has_topic_filter_mqtt_3_10_3_2(&p, 1);
T_ASSERT_MSG(p.payload.topic_count == 1, "wrapper must ensure topic_count");
T_ASSERT_MSG(p.payload.topic_filters[0][0] != '\0', "topic_filter must be non-empty");
return 0;
}


static int test_fix_unsubscribe_reserved_flags(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_UNSUBSCRIBE << 4) | 0x00u);
fix_unsubscribe_reserved_flags(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "UNSUBSCRIBE reserved flags must be 0x2");
return 0;
}


static int test_fix_unsubscribe_utf8_topic_filters(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.payload.topic_count = 1;
memset(p.payload.topic_filters[0], 0xFF, sizeof(p.payload.topic_filters[0]));
p.payload.topic_filters[0][0] = 'a';
p.payload.topic_filters[0][1] = '/';
fix_unsubscribe_utf8_topic_filters(&p, 1);
T_ASSERT_MSG(p.payload.topic_filters[0][MAX_TOPIC_LEN-1] == '\0', "unsubscribe topic_filter must be NUL terminated");
T_ASSERT_MSG(p.payload.topic_filters[0][0] != '\0', "unsubscribe topic_filter must be non-empty");
T_ASSERT_MSG(is_ascii_printable(p.payload.topic_filters[0]), "unsubscribe topic_filter must be ASCII after sanitization");
return 0;
}


static int test_fix_unsubscribe_packet_identifier(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 0;
fix_unsubscribe_packet_identifier(&p, 1);
T_ASSERT_MSG(p.variable_header.packet_identifier != 0, "unsubscribe packet_identifier must be non-zero");
return 0;
}


static int test_fix_unsubscribe_all_length(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 9;
p.variable_header.property_len = 0;
p.payload.topic_count = 2;
snprintf(p.payload.topic_filters[0], sizeof(p.payload.topic_filters[0]), "a/#");
snprintf(p.payload.topic_filters[1], sizeof(p.payload.topic_filters[1]), "b");
fix_unsubscribe_all_length(&p, 1);

size_t payload_len = 0;
payload_len += 2 + strlen("a/#");
payload_len += 2 + strlen("b");
size_t vh_len = 2 + p.variable_header.property_len;
size_t expected = vh_len + payload_len;
T_ASSERT_MSG(p.fixed_header.remaining_length == expected, "unsubscribe remaining_length must match computed size");
return 0;
}


static int test_fix_unsubscribe(void) {
mqtt_unsubscribe_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_UNSUBSCRIBE << 4) | 0x00u);
p.variable_header.packet_identifier = 0;
p.payload.topic_count = 0;
fix_unsubscribe(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "unsubscribe wrapper should fix reserved flags");
T_ASSERT_MSG(p.variable_header.packet_identifier != 0, "unsubscribe wrapper should set packet_identifier");
T_ASSERT_MSG(p.payload.topic_count >= 1, "unsubscribe wrapper should ensure topic_count >= 1");
return 0;
}


static int test_fix_publish_topic_name_utf8(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
/* empty topic -> should become non-empty */
p.variable_header.topic_name[0] = '\0';
fix_publish_topic_name_utf8(&p, 1);
T_ASSERT_MSG(p.variable_header.topic_name[0] != '\0', "topic_name must be non-empty");
T_ASSERT_MSG(is_ascii_printable(p.variable_header.topic_name), "topic_name must be ASCII after sanitization");
return 0;
}


static int test_fix_publish_topic_name_no_wildcards(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "a/+/b/#");
fix_publish_topic_name_no_wildcards(&p, 1);
T_ASSERT_MSG(!has_wildcard(p.variable_header.topic_name), "topic_name must not contain wildcards");
T_ASSERT_MSG(p.variable_header.topic_name[0] != '\0', "topic_name must be non-empty after stripping wildcards");
return 0;
}


static int test_fix_publish_topic_name_no_wildcards_mqtt_4_7_0_1(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "x/#");
fix_publish_topic_name_no_wildcards_mqtt_4_7_0_1(&p, 1);
T_ASSERT_MSG(!has_wildcard(p.variable_header.topic_name), "MQTT-4.7.0-1: topic_name must not contain wildcards");
return 0;
}


static int test_fix_publish_match_subscription_filter(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "t");
fix_publish_match_subscription_filter(&p, 1);
T_ASSERT_MSG(strcmp(p.variable_header.topic_name, "t") == 0, "match_subscription_filter should not mutate topic_name in current implementation");
return 0;
}


static int test_fix_publish_topic_name_length_and_nul(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
memset(p.variable_header.topic_name, 'A', sizeof(p.variable_header.topic_name));
p.variable_header.topic_name[sizeof(p.variable_header.topic_name)-1] = 'B'; /* no NUL */
fix_publish_topic_name_length_and_nul(&p, 1);
T_ASSERT_MSG(p.variable_header.topic_name[MAX_TOPIC_LEN-1] == '\0', "topic_name must be NUL terminated");
return 0;
}


static int test_fix_publish_packet_identifier(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));

/* qos=0 => Packet Identifier MUST be absent */
p.qos = 0;
p.variable_header.packet_identifier = 0x1234;
fix_publish_packet_identifier(&p, 1);
T_ASSERT_MSG(p.variable_header.packet_identifier == 0, "qos=0 => packet_identifier must be 0");

/* qos>0: this fixer does NOT guarantee setting a non-zero id; it should not clobber a valid id */
memset(&p, 0, sizeof(p));
p.qos = 1;
p.variable_header.packet_identifier = 0x2222;
fix_publish_packet_identifier(&p, 1);
T_ASSERT_MSG(p.variable_header.packet_identifier == 0x2222, "qos>0 => should not clear an existing packet_identifier");
return 0;
}


static int test_fix_publish_packet_identifier_unique(void) {
mqtt_publish_packet_t pkts[2];
memset(pkts, 0, sizeof(pkts));
memset(packet_id_used, 0, sizeof(packet_id_used));

pkts[0].qos = 1;
pkts[1].qos = 1;
pkts[0].variable_header.packet_identifier = 10;
pkts[1].variable_header.packet_identifier = 10;

fix_publish_packet_identifier_unique(pkts, 2);
T_ASSERT_MSG(pkts[0].variable_header.packet_identifier == 10, "first packet may keep its id");
T_ASSERT_MSG(pkts[1].variable_header.packet_identifier != 0, "second packet id must be non-zero");
T_ASSERT_MSG(pkts[1].variable_header.packet_identifier != 10, "second packet id must be changed to be unique");
return 0;
}


static int test_fix_publish_dup_flag(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
p.qos = 0;
p.dup = 1;
fix_publish_dup_flag(&p, 1);
T_ASSERT_MSG(p.dup == 0, "qos=0 => dup must be 0");
return 0;
}


static int test_fix_publish_qos_bits(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
p.qos = 7;
fix_publish_qos_bits(&p, 1);
T_ASSERT_MSG(p.qos <= 2, "qos must be clamped to [0,2]");
return 0;
}


static int test_fix_publish_topic_alias(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "t");
/* two alias properties: first is > max, second should be dropped */
p.variable_header.property_len = 6;
p.variable_header.properties[0] = T_PROP_ID_TOPIC_ALIAS;
p.variable_header.properties[1] = 0x00;
p.variable_header.properties[2] = 0x0B; /* 11 */
p.variable_header.properties[3] = T_PROP_ID_TOPIC_ALIAS;
p.variable_header.properties[4] = 0x00;
p.variable_header.properties[5] = 0x02;

fix_publish_topic_alias(&p, 1, 10);

uint16_t alias = 0;
T_ASSERT_MSG(p.variable_header.property_len == 3, "only one Topic Alias property should remain");
T_ASSERT_MSG(props_get_topic_alias_u16(p.variable_header.properties, p.variable_header.property_len, &alias), "Topic Alias must exist");
T_ASSERT_MSG(alias == 10, "Topic Alias must be clamped to connack_alias_max");

/* connack_alias_max=0: allow alias only when topic_name is empty */
memset(&p, 0, sizeof(p));
p.variable_header.topic_name[0] = '\0';
p.variable_header.property_len = 3;
p.variable_header.properties[0] = T_PROP_ID_TOPIC_ALIAS;
p.variable_header.properties[1] = 0x00;
p.variable_header.properties[2] = 0x00; /* invalid 0 -> should become 1 */

fix_publish_topic_alias(&p, 1, 0);

alias = 0;
T_ASSERT_MSG(p.variable_header.property_len == 3, "Topic Alias should be kept when topic_name is empty");
T_ASSERT_MSG(props_get_topic_alias_u16(p.variable_header.properties, p.variable_header.property_len, &alias), "Topic Alias must exist");
T_ASSERT_MSG(alias == 1, "Topic Alias 0 must be corrected to 1");
return 0;
}


static int test_fix_publish_response_topic(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));

/* build: Response Topic 'a/#' (invalid), then Response Topic 'ok/topic' (valid) */
const char *bad = "a/#";
const char *good = "ok/topic";
uint8_t *q = p.variable_header.properties;
size_t off = 0;

q[off++] = T_PROP_ID_RESPONSE_TOPIC;
q[off++] = 0x00; q[off++] = (uint8_t)strlen(bad);
memcpy(&q[off], bad, strlen(bad)); off += strlen(bad);

q[off++] = T_PROP_ID_RESPONSE_TOPIC;
q[off++] = 0x00; q[off++] = (uint8_t)strlen(good);
memcpy(&q[off], good, strlen(good)); off += strlen(good);

p.variable_header.property_len = (uint32_t)off;

fix_publish_response_topic(&p, 1);

char out[256];
memset(out, 0, sizeof(out));
T_ASSERT_MSG(props_get_first_response_topic(p.variable_header.properties, p.variable_header.property_len, out, sizeof(out)), "must find one Response Topic after fix");
T_ASSERT_MSG(strcmp(out, good) == 0, "Response Topic must be the first valid one (wildcards removed)");
T_ASSERT_MSG(!has_wildcard(out), "Response Topic must not contain wildcards");
T_ASSERT_MSG(props_count_id(p.variable_header.properties, p.variable_header.property_len, T_PROP_ID_RESPONSE_TOPIC) == 1, "only one Response Topic property should remain");
return 0;
}


static int test_fix_publish_subscription_identifier(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));

/* build properties: SUB_ID=123, plus a Response Topic that should remain */
uint8_t *q = p.variable_header.properties;
size_t off = 0;

q[off++] = T_PROP_ID_SUB_ID;
uint8_t tmp[8];
size_t n = enc_varint(123, tmp, sizeof(tmp));
memcpy(&q[off], tmp, n); off += n;

const char *good = "ok/topic";
q[off++] = T_PROP_ID_RESPONSE_TOPIC;
q[off++] = 0x00; q[off++] = (uint8_t)strlen(good);
memcpy(&q[off], good, strlen(good)); off += strlen(good);

p.variable_header.property_len = (uint32_t)off;

fix_publish_subscription_identifier(&p, 1);

T_ASSERT_MSG(!props_has_sub_id(p.variable_header.properties, p.variable_header.property_len), "SUB_ID property must be removed from PUBLISH");
char out[256];
memset(out, 0, sizeof(out));
T_ASSERT_MSG(props_get_first_response_topic(p.variable_header.properties, p.variable_header.property_len, out, sizeof(out)), "Response Topic should remain");
T_ASSERT_MSG(strcmp(out, good) == 0, "Response Topic value should be preserved");
return 0;
}


static int test_fix_publish_delivery_protocol(void) {
mqtt_publish_packet_t pkts[2];
memset(pkts, 0, sizeof(pkts));
memset(packet_id_used, 0, sizeof(packet_id_used));

pkts[0].qos = 1;
pkts[1].qos = 1;
pkts[0].dup = 1;
pkts[1].dup = 1;
pkts[0].variable_header.packet_identifier = 5;
pkts[1].variable_header.packet_identifier = 5;
packet_id_used[5] = 1; /* force re-assign */

fix_publish_delivery_protocol(pkts, 2);

T_ASSERT_MSG(pkts[0].variable_header.packet_identifier != 0, "packet_id must be non-zero when qos>0");
T_ASSERT_MSG(pkts[1].variable_header.packet_identifier != 0, "packet_id must be non-zero when qos>0");
T_ASSERT_MSG(pkts[0].dup == 0 && pkts[1].dup == 0, "dup must be 0 after reassigning id");

/* qos=0 => dup=0 and packet_id=0 */
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
p.qos = 0;
p.dup = 1;
p.variable_header.packet_identifier = 9;
fix_publish_delivery_protocol(&p, 1);
T_ASSERT_MSG(p.dup == 0, "qos=0 => dup=0");
T_ASSERT_MSG(p.variable_header.packet_identifier == 0, "qos=0 => packet_id=0");
return 0;
}


static int test_fix_publish_all_length(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));
snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "abc");
p.qos = 1;
p.variable_header.packet_identifier = 0x1234;

/* properties: one Topic Alias (3 bytes) */
p.variable_header.property_len = 3;
p.variable_header.properties[0] = T_PROP_ID_TOPIC_ALIAS;
p.variable_header.properties[1] = 0x00;
p.variable_header.properties[2] = 0x02;

/* payload present but payload_len wrong (should be strlen) */
snprintf(p.payload.payload, sizeof(p.payload.payload), "HELLO");
p.payload.payload_len = 0;

fix_publish_all_length(&p, 1);

T_ASSERT_MSG(p.payload.payload_len == 5, "payload_len should be derived from strlen(payload)");

size_t topic_len = strlen("abc");
size_t var_header_len = 2 + topic_len; /* topic length field + string */
var_header_len += 2; /* packet id for qos>0 */
var_header_len += 1; /* property length encoded (simplified to 1 byte in fixer) */
var_header_len += p.variable_header.property_len;
size_t expected = var_header_len + p.payload.payload_len;

T_ASSERT_MSG(p.fixed_header.remaining_length == expected, "publish remaining_length must match computed size");
return 0;
}


static int test_fix_publish(void) {
mqtt_publish_packet_t p;
memset(&p, 0, sizeof(p));

snprintf(p.variable_header.topic_name, sizeof(p.variable_header.topic_name), "a/+/b/#");
p.qos = 0;
p.dup = 1;
p.variable_header.packet_identifier = 0x2222; /* invalid for qos=0 */

/* properties: SUB_ID + bad response topic + good response topic */
uint8_t *q = p.variable_header.properties;
size_t off = 0;

q[off++] = T_PROP_ID_SUB_ID;
uint8_t tmp[8];
size_t n = enc_varint(7, tmp, sizeof(tmp));
memcpy(&q[off], tmp, n); off += n;

const char *bad = "a/#";
q[off++] = T_PROP_ID_RESPONSE_TOPIC;
q[off++] = 0x00; q[off++] = (uint8_t)strlen(bad);
memcpy(&q[off], bad, strlen(bad)); off += strlen(bad);

const char *good = "ok/topic";
q[off++] = T_PROP_ID_RESPONSE_TOPIC;
q[off++] = 0x00; q[off++] = (uint8_t)strlen(good);
memcpy(&q[off], good, strlen(good)); off += strlen(good);

p.variable_header.property_len = (uint32_t)off;

fix_publish(&p, 1);

T_ASSERT_MSG(!has_wildcard(p.variable_header.topic_name), "publish wrapper must strip wildcards from topic_name");
T_ASSERT_MSG(p.qos <= 2, "publish wrapper must ensure qos in [0,2]");
T_ASSERT_MSG(p.variable_header.packet_identifier == 0, "publish wrapper must clear packet_id when qos=0");
T_ASSERT_MSG(p.dup == 0, "publish wrapper must clear dup when qos=0");
T_ASSERT_MSG(!props_has_sub_id(p.variable_header.properties, p.variable_header.property_len), "publish wrapper must remove SUB_ID");
char out[256];
memset(out, 0, sizeof(out));
T_ASSERT_MSG(props_get_first_response_topic(p.variable_header.properties, p.variable_header.property_len, out, sizeof(out)), "publish wrapper must keep a Response Topic");
T_ASSERT_MSG(strcmp(out, good) == 0, "publish wrapper must keep the first valid Response Topic");
return 0;
}


static int test_fix_pubrel_reserved_flags(void) {
mqtt_pubrel_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_PUBREL << 4) | 0x00u);
fix_pubrel_reserved_flags(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "PUBREL reserved flags must be 0x2");
return 0;
}


static int test_fix_pubrel_reason_code_valid(void) {
mqtt_pubrel_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_pubrel_reason_code_valid(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "invalid PUBREL reason_code must be fixed to 0");
return 0;
}


static int test_fix_pubrel(void) {
mqtt_pubrel_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_PUBREL << 4) | 0x00u);
p.variable_header.reason_code = 0xFF;
fix_pubrel(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x02u, "pubrel wrapper fixes reserved flags");
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "pubrel wrapper fixes reason_code");
return 0;
}


static int test_fix_puback_reason_code_valid(void) {
mqtt_puback_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_puback_reason_code_valid(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "invalid PUBACK reason_code must be fixed to 0");
return 0;
}


static int test_fix_puback(void) {
mqtt_puback_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_puback(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "puback wrapper fixes reason_code");
return 0;
}


static int test_fix_auth_reserved_flags(void) {
mqtt_auth_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_AUTH << 4) | 0x0Fu);
fix_auth_reserved_flags(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x00u, "AUTH reserved flags must be 0");
return 0;
}


static int test_fix_auth_reason_code_valid(void) {
mqtt_auth_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_auth_reason_code_valid(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "invalid AUTH reason_code must be fixed to 0");
return 0;
}


static int test_fix_auth_all_length(void) {
mqtt_auth_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.property_len = 7;
fix_auth_all_length(&p, 1);
T_ASSERT_MSG(p.fixed_header.remaining_length == (size_t)(1 + p.variable_header.property_len), "AUTH remaining_length must be 1 + property_len");
return 0;
}


static int test_fix_auth(void) {
mqtt_auth_packet_t p;
memset(&p, 0, sizeof(p));
p.fixed_header.packet_type = (uint8_t)((MQTT_AUTH << 4) | 0x0Fu);
p.variable_header.reason_code = 0xFF;
p.variable_header.property_len = 5;
fix_auth(&p, 1);
T_ASSERT_MSG((p.fixed_header.packet_type & 0x0Fu) == 0x00u, "auth wrapper fixes reserved flags");
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "auth wrapper fixes reason_code");
T_ASSERT_MSG(p.fixed_header.remaining_length == (size_t)(1 + p.variable_header.property_len), "auth wrapper fixes remaining_length");
return 0;
}


static int test_fix_disconnect_reason_code_valid(void) {
mqtt_disconnect_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_disconnect_reason_code_valid(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "invalid DISCONNECT reason_code must be fixed to 0");
return 0;
}


static int test_fix_disconnect(void) {
mqtt_disconnect_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.reason_code = 0xFF;
fix_disconnect(&p, 1);
T_ASSERT_MSG(p.variable_header.reason_code == 0x00, "disconnect wrapper fixes reason_code");
return 0;
}


static int test_fix_pubrec(void) {
mqtt_pubrec_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 1;
p.variable_header.reason_code = 0x00;
fix_pubrec(&p, 1);
T_ASSERT(1); /* just no crash */
return 0;
}


static int test_fix_pubcomp(void) {
mqtt_pubcomp_packet_t p;
memset(&p, 0, sizeof(p));
p.variable_header.packet_identifier = 1;
p.variable_header.reason_code = 0x00;
fix_pubcomp(&p, 1);
T_ASSERT(1);
return 0;
}


static int test_fix_pingreq(void) {
mqtt_pingreq_packet_t p;
memset(&p, 0, sizeof(p));
fix_pingreq(&p, 1);
T_ASSERT(1);
return 0;
}


static int test_fix_mqtt(void) {
mqtt_packet_t msgs[3];
memset(msgs, 0, sizeof(msgs));

msgs[0].type = TYPE_CONNECT;
snprintf(msgs[0].connect.variable_header.protocol_name, sizeof(msgs[0].connect.variable_header.protocol_name), "BAD");
msgs[0].connect.variable_header.protocol_level = 5;
snprintf(msgs[0].connect.payload.client_id, sizeof(msgs[0].connect.payload.client_id), "cid");
mqtt_set_bit(&msgs[0].connect.variable_header.connect_flags, MQTT_CF_USERNAME, 1);
msgs[0].connect.payload.user_name[0] = '\0';

msgs[1].type = TYPE_PUBLISH;
snprintf(msgs[1].publish.variable_header.topic_name, sizeof(msgs[1].publish.variable_header.topic_name), "a/+/b/#");
msgs[1].publish.qos = 0;
msgs[1].publish.dup = 1;
msgs[1].publish.variable_header.packet_identifier = 0x4444;

msgs[2].type = TYPE_SUBSCRIBE;
msgs[2].subscribe.fixed_header.packet_type = (uint8_t)((MQTT_SUBSCRIBE << 4) | 0x00u);
msgs[2].subscribe.variable_header.packet_identifier = 0;
msgs[2].subscribe.payload.topic_count = 0;

fix_mqtt(msgs, 3);

T_ASSERT_MSG(strcmp(msgs[0].connect.variable_header.protocol_name, "MQTT") == 0, "fix_mqtt should fix CONNECT protocol_name");
T_ASSERT_MSG(msgs[0].connect.payload.user_name[0] != '\0', "fix_mqtt should fix CONNECT username presence");
T_ASSERT_MSG(!has_wildcard(msgs[1].publish.variable_header.topic_name), "fix_mqtt should strip wildcards from PUBLISH topic_name");
T_ASSERT_MSG(msgs[1].publish.variable_header.packet_identifier == 0, "fix_mqtt should clear PUBLISH packet_id when qos=0");
T_ASSERT_MSG((msgs[2].subscribe.fixed_header.packet_type & 0x0Fu) == 0x02u, "fix_mqtt should fix SUBSCRIBE reserved flags");
T_ASSERT_MSG(msgs[2].subscribe.payload.topic_count >= 1, "fix_mqtt should ensure SUBSCRIBE topic_count >= 1");
return 0;
}


typedef int (*test_fn_t)(void);

typedef struct { const char *name; test_fn_t fn; } test_case_t;


static test_case_t kTests[] = {

  {"fix_unsubscribe_payload_has_topic_filter", test_fix_unsubscribe_payload_has_topic_filter},

  {"fix_unsubscribe_payload_has_topic_filter_mqtt_3_10_3_2", test_fix_unsubscribe_payload_has_topic_filter_mqtt_3_10_3_2},

  {"fix_connect_protocol_name_mqtt", test_fix_connect_protocol_name_mqtt},

  {"fix_publish_topic_name_utf8", test_fix_publish_topic_name_utf8},

  {"fix_publish_topic_name_no_wildcards", test_fix_publish_topic_name_no_wildcards},

  {"fix_publish_topic_name_no_wildcards_mqtt_4_7_0_1", test_fix_publish_topic_name_no_wildcards_mqtt_4_7_0_1},

  {"fix_publish_match_subscription_filter", test_fix_publish_match_subscription_filter},

  {"fix_pubrel_reserved_flags", test_fix_pubrel_reserved_flags},

  {"fix_pubrel_reason_code_valid", test_fix_pubrel_reason_code_valid},

  {"fix_puback_reason_code_valid", test_fix_puback_reason_code_valid},

  {"fix_subscribe_reserved_flags", test_fix_subscribe_reserved_flags},

  {"fix_subscribe_topic_filters_utf8", test_fix_subscribe_topic_filters_utf8},

  {"fix_subscribe_payload_has_topic_pair", test_fix_subscribe_payload_has_topic_pair},

  {"fix_disconnect_reason_code_valid", test_fix_disconnect_reason_code_valid},

  {"fix_auth_reserved_flags", test_fix_auth_reserved_flags},

  {"fix_auth_reason_code_valid", test_fix_auth_reason_code_valid},

  {"fix_publish_topic_name_length_and_nul", test_fix_publish_topic_name_length_and_nul},

  {"fix_sub_unsub_topic_filters_length_and_nul", test_fix_sub_unsub_topic_filters_length_and_nul},

  {"fix_subscribe_shared_subscription_filters", test_fix_subscribe_shared_subscription_filters},

  {"fix_connect_packet_will_rules", test_fix_connect_packet_will_rules},

  {"fix_user_name_flag", test_fix_user_name_flag},

  {"fix_password_flag", test_fix_password_flag},

  {"fix_connect_all_length", test_fix_connect_all_length},

  {"fix_publish_packet_identifier", test_fix_publish_packet_identifier},

  {"fix_publish_packet_identifier_unique", test_fix_publish_packet_identifier_unique},

  {"fix_publish_dup_flag", test_fix_publish_dup_flag},

  {"fix_publish_qos_bits", test_fix_publish_qos_bits},

  {"fix_publish_topic_alias", test_fix_publish_topic_alias},

  {"fix_publish_response_topic", test_fix_publish_response_topic},

  {"fix_publish_subscription_identifier", test_fix_publish_subscription_identifier},

  {"fix_publish_delivery_protocol", test_fix_publish_delivery_protocol},

  {"fix_subscribe_no_local", test_fix_subscribe_no_local},

  {"fix_subscribe_packet_identifier", test_fix_subscribe_packet_identifier},

  {"fix_subscribe_packet_identifier_unique", test_fix_subscribe_packet_identifier_unique},

  {"fix_subscribe_all_length", test_fix_subscribe_all_length},

  {"fix_publish_all_length", test_fix_publish_all_length},

  {"fix_unsubscribe_reserved_flags", test_fix_unsubscribe_reserved_flags},

  {"fix_unsubscribe_utf8_topic_filters", test_fix_unsubscribe_utf8_topic_filters},

  {"fix_unsubscribe_packet_identifier", test_fix_unsubscribe_packet_identifier},

  {"fix_unsubscribe_all_length", test_fix_unsubscribe_all_length},

  {"fix_auth_all_length", test_fix_auth_all_length},

  {"fix_connect", test_fix_connect},

  {"fix_subscribe", test_fix_subscribe},

  {"fix_publish", test_fix_publish},

  {"fix_unsubscribe", test_fix_unsubscribe},

  {"fix_auth", test_fix_auth},

  {"fix_pubrel", test_fix_pubrel},

  {"fix_puback", test_fix_puback},

  {"fix_pubrec", test_fix_pubrec},

  {"fix_pubcomp", test_fix_pubcomp},

  {"fix_pingreq", test_fix_pingreq},

  {"fix_disconnect", test_fix_disconnect},

  {"fix_mqtt", test_fix_mqtt},

};


int main(void) {
  srand(0);

  int total = (int)(sizeof(kTests) / sizeof(kTests[0]));
  int failed = 0;
  const char *failed_names[256];
  if (total > 256) {
    fprintf(stderr, "Too many tests (%d)", total);
    return 2;
  }

  printf("[MQTT Fixer Sanity] Running %d tests...\n", total);
  for (int i = 0; i < total; ++i) {
    const char *name = kTests[i].name;
    printf("- %s\n", name);
    int r = kTests[i].fn();
    if (r != 0) {
      failed_names[failed++] = name;
      printf("  => FAIL\n");
    } else {
      printf("  => PASS\n");
    }
  }

  printf("\n[MQTT Fixer Sanity] Done. failed=%d/%d\n", failed, total);
  if (failed) {
    printf("Failing fixers:\n");
    for (int i = 0; i < failed; ++i) {
      printf("  - %s\n", failed_names[i]);
    }
  }
  return failed ? 1 : 0;
}
