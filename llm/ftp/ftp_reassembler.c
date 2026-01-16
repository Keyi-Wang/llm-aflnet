/* ftp reassembler source file */
#include "ftp.h"

#include <stdint.h>
#include <string.h>


#ifndef u8
typedef uint8_t  u8;
#endif
#ifndef u32
typedef uint32_t u32;
#endif


static int out_put(u8 *out, u32 cap, u32 *pos, const char *s) {
    if (!s || !*s) return 1;               
    size_t n = strlen(s);
    if (*pos > cap || cap - *pos < n) return 0;  
    memcpy(out + *pos, s, n);
    *pos += (u32)n;
    return 1;
}


static int out_put_if_nonempty(u8 *out, u32 cap, u32 *pos,
                               const char *maybe_space, const char *field) {
    if (!field || !*field) return 1;        
    if (maybe_space && *maybe_space) {
        if (!out_put(out, cap, pos, maybe_space)) return 0;
    }
    return out_put(out, cap, pos, field);
}


static int reassemble_one(const ftp_packet_t *p, u8 *out, u32 cap, u32 *pos) {
    switch (p->command_type) {
        case FTP_CDUP: if (!out_put(out,cap,pos,p->packet.cdup.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.cdup.crlf))    return 0; break;
        case FTP_QUIT: if (!out_put(out,cap,pos,p->packet.quit.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.quit.crlf))    return 0; break;
        case FTP_REIN: if (!out_put(out,cap,pos,p->packet.rein.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.rein.crlf))    return 0; break;
        case FTP_PASV: if (!out_put(out,cap,pos,p->packet.pasv.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.pasv.crlf))    return 0; break;
        case FTP_ABOR: if (!out_put(out,cap,pos,p->packet.abor.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.abor.crlf))    return 0; break;
        case FTP_PWD:  if (!out_put(out,cap,pos,p->packet.pwd.command))  return 0;
                       if (!out_put(out,cap,pos,p->packet.pwd.crlf))     return 0; break;
        case FTP_SYST: if (!out_put(out,cap,pos,p->packet.syst.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.syst.crlf))    return 0; break;
        case FTP_NOOP: if (!out_put(out,cap,pos,p->packet.noop.command)) return 0;
                       if (!out_put(out,cap,pos,p->packet.noop.crlf))    return 0; break;

        case FTP_USER:
            if (!out_put(out,cap,pos,p->packet.user.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.user.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.user.username))  return 0;
            if (!out_put(out,cap,pos,p->packet.user.crlf))      return 0;
            break;
        case FTP_PASS:
            if (!out_put(out,cap,pos,p->packet.pass.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.pass.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.pass.password))  return 0;
            if (!out_put(out,cap,pos,p->packet.pass.crlf))      return 0;
            break;
        case FTP_ACCT:
            if (!out_put(out,cap,pos,p->packet.acct.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.acct.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.acct.account_info)) return 0;
            if (!out_put(out,cap,pos,p->packet.acct.crlf))      return 0;
            break;
        case FTP_CWD:
            if (!out_put(out,cap,pos,p->packet.cwd.command))    return 0;
            if (!out_put(out,cap,pos,p->packet.cwd.space))      return 0;
            if (!out_put(out,cap,pos,p->packet.cwd.pathname))   return 0;
            if (!out_put(out,cap,pos,p->packet.cwd.crlf))       return 0;
            break;
        case FTP_SMNT:
            if (!out_put(out,cap,pos,p->packet.smnt.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.smnt.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.smnt.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.smnt.crlf))      return 0;
            break;
        case FTP_PORT:
            if (!out_put(out,cap,pos,p->packet.port.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.port.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.port.host_port_str)) return 0;
            if (!out_put(out,cap,pos,p->packet.port.crlf))      return 0;
            break;
        case FTP_STRU:
            if (!out_put(out,cap,pos,p->packet.stru.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.stru.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.stru.structure_code)) return 0;
            if (!out_put(out,cap,pos,p->packet.stru.crlf))      return 0;
            break;
        case FTP_MODE:
            if (!out_put(out,cap,pos,p->packet.mode.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.mode.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.mode.mode_code)) return 0;
            if (!out_put(out,cap,pos,p->packet.mode.crlf))      return 0;
            break;
        case FTP_RETR:
            if (!out_put(out,cap,pos,p->packet.retr.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.retr.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.retr.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.retr.crlf))      return 0;
            break;
        case FTP_STOR:
            if (!out_put(out,cap,pos,p->packet.stor.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.stor.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.stor.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.stor.crlf))      return 0;
            break;
        case FTP_APPE:
            if (!out_put(out,cap,pos,p->packet.appe.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.appe.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.appe.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.appe.crlf))      return 0;
            break;
        case FTP_REST:
            if (!out_put(out,cap,pos,p->packet.rest.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.rest.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.rest.marker))    return 0;
            if (!out_put(out,cap,pos,p->packet.rest.crlf))      return 0;
            break;
        case FTP_RNFR:
            if (!out_put(out,cap,pos,p->packet.rnfr.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.rnfr.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.rnfr.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.rnfr.crlf))      return 0;
            break;
        case FTP_RNTO:
            if (!out_put(out,cap,pos,p->packet.rnto.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.rnto.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.rnto.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.rnto.crlf))      return 0;
            break;
        case FTP_DELE:
            if (!out_put(out,cap,pos,p->packet.dele.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.dele.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.dele.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.dele.crlf))      return 0;
            break;
        case FTP_RMD:
            if (!out_put(out,cap,pos,p->packet.rmd.command))    return 0;
            if (!out_put(out,cap,pos,p->packet.rmd.space))      return 0;
            if (!out_put(out,cap,pos,p->packet.rmd.pathname))   return 0;
            if (!out_put(out,cap,pos,p->packet.rmd.crlf))       return 0;
            break;
        case FTP_MKD:
            if (!out_put(out,cap,pos,p->packet.mkd.command))    return 0;
            if (!out_put(out,cap,pos,p->packet.mkd.space))      return 0;
            if (!out_put(out,cap,pos,p->packet.mkd.pathname))   return 0;
            if (!out_put(out,cap,pos,p->packet.mkd.crlf))       return 0;
            break;
        case FTP_SITE:
            if (!out_put(out,cap,pos,p->packet.site.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.site.space))     return 0;
            if (!out_put(out,cap,pos,p->packet.site.parameters))return 0;
            if (!out_put(out,cap,pos,p->packet.site.crlf))      return 0;
            break;


        case FTP_TYPE:
            if (!out_put(out,cap,pos,p->packet.type.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.type.space1))    return 0;
            if (!out_put(out,cap,pos,p->packet.type.type_code)) return 0;
            if (p->packet.type.format_control[0]) {
                if (!out_put(out,cap,pos,p->packet.type.space2))       return 0;
                if (!out_put(out,cap,pos,p->packet.type.format_control)) return 0;
            }
            if (!out_put(out,cap,pos,p->packet.type.crlf))      return 0;
            break;

        case FTP_ALLO:
            if (!out_put(out,cap,pos,p->packet.allo.command))   return 0;
            if (!out_put(out,cap,pos,p->packet.allo.space1))    return 0;
            if (!out_put(out,cap,pos,p->packet.allo.byte_count))return 0;
            if (p->packet.allo.record_format[0]) {
                if (!out_put(out,cap,pos,p->packet.allo.space2))      return 0;
                if (!out_put(out,cap,pos,p->packet.allo.record_format)) return 0;
            }
            if (!out_put(out,cap,pos,p->packet.allo.crlf))      return 0;
            break;

        case FTP_STOU:
            if (!out_put(out,cap,pos,p->packet.stou.command))   return 0;
            if (!out_put_if_nonempty(out,cap,pos,p->packet.stou.space,
                                     p->packet.stou.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.stou.crlf))      return 0;
            break;
        case FTP_LIST:
            if (!out_put(out,cap,pos,p->packet.list.command))   return 0;
            if (!out_put_if_nonempty(out,cap,pos,p->packet.list.space,
                                     p->packet.list.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.list.crlf))      return 0;
            break;
        case FTP_NLST:
            if (!out_put(out,cap,pos,p->packet.nlst.command))   return 0;
            if (!out_put_if_nonempty(out,cap,pos,p->packet.nlst.space,
                                     p->packet.nlst.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.nlst.crlf))      return 0;
            break;
        case FTP_STAT:
            if (!out_put(out,cap,pos,p->packet.stat.command))   return 0;
            if (!out_put_if_nonempty(out,cap,pos,p->packet.stat.space,
                                     p->packet.stat.pathname))  return 0;
            if (!out_put(out,cap,pos,p->packet.stat.crlf))      return 0;
            break;
        case FTP_HELP:
            if (!out_put(out,cap,pos,p->packet.help.command))   return 0;
            if (!out_put_if_nonempty(out,cap,pos,p->packet.help.space,
                                     p->packet.help.argument))  return 0;
            if (!out_put(out,cap,pos,p->packet.help.crlf))      return 0;
            break;

        default:
            return 0; 
    }
    return 1;
}

int reassemble_ftp_msgs(const ftp_packet_t *packets, u32 num_packets,
                        u8 *output_buf, u32 *out_len)
{
    if (!packets || !output_buf || !out_len) return -1;
    u32 cap = 1024*1024;
    u32 pos = 0;

    for (u32 i = 0; i < num_packets; ++i) {
        if (!reassemble_one(&packets[i], output_buf, cap, &pos)) {
            *out_len = pos;
            return -2; 
        }
    }

    *out_len = pos;
    return 0;
}
