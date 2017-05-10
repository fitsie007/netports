package fitz.pcap.dto;


import fitz.pcap.util.Utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * The Class Packet.
 */
public class Packet
{
    private static final Pattern PACKET_INFO_PATTERN = Pattern.compile( "^(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}.\\d{3})(\\d{3})\\s+IP\\s+\\((.*)\\)\\s+(\\S+)\\s+>\\s+([^:]*):(.*)$" );
    private static final Pattern PROTO_PATTERN       = Pattern.compile( "^([^\\(]+)\\((\\d+)\\)$" );
    private static final Pattern EXTRA_FLAGS_PATTERN = Pattern.compile( "Flags\\s+\\[([^\\]]*)\\]" );
    private static final SimpleDateFormat DATE_FORMAT         = new SimpleDateFormat( "yyyy-MM-dd HH:mm:ss.SSS" );
    private static final DecimalFormat MICROSECONDS_FORMAT = new DecimalFormat( "000" );

    private String _rawPacketStr;
    private long                          _time;
    private int                           _microseconds;
    private int                           _tos;
    private int                           _ttl;
    private int                           _identifier;
    private int                           _offset;
    private String _flags;
    private String _extraFlags;
    private int                           _protocolId;
    private String _protocol;
    private int                           _length;
    private int                           _packets = 1;
    private InetAddress _src;
    private String _srcPort;
    private InetAddress _dst;
    private String _dstPort;
    private String _extraInfo;

    /**
     * Gets the time.
     *
     * @return the time
     */
    public long getTime()
    {
        return _time;
    }

    /**
     * Sets the time.
     *
     * @param time the new time
     */
    public void setTime( long time )
    {
        _time = time;
    }

    /**
     * Gets the end time.
     *
     * @return the end time
     */
    public long getEndTime()
    {
        return _time + 1;
    }

    /**
     * Gets the microseconds.
     *
     * @return the microseconds
     */
    public int getMicroseconds()
    {
        return _microseconds;
    }

    /**
     * Sets the microseconds.
     *
     * @param microseconds the new microseconds
     */
    public void setMicroseconds( int microseconds )
    {
        _microseconds = microseconds;
    }

    /**
     * Gets the tos.
     *
     * @return the tos
     */
    public int getTos()
    {
        return _tos;
    }

    /**
     * Sets the tos.
     *
     * @param tos the new tos
     */
    public void setTos( int tos )
    {
        _tos = tos;
    }

    /**
     * Gets the ttl.
     *
     * @return the ttl
     */
    public int getTtl()
    {
        return _ttl;
    }

    /**
     * Sets the ttl.
     *
     * @param ttl the new ttl
     */
    public void setTtl( int ttl )
    {
        _ttl = ttl;
    }

    /**
     * Gets the identifier.
     *
     * @return the identifier
     */
    public int getIdentifier()
    {
        return _identifier;
    }

    /**
     * Sets the identifier.
     *
     * @param identifier the new identifier
     */
    public void setIdentifier( int identifier )
    {
        _identifier = identifier;
    }

    /**
     * Gets the offset.
     *
     * @return the offset
     */
    public int getOffset()
    {
        return _offset;
    }

    /**
     * Sets the offset.
     *
     * @param offset the new offset
     */
    public void setOffset( int offset )
    {
        _offset = offset;
    }

    /**
     * Gets the flags.
     *
     * @return the flags
     */
    public String getFlags()
    {
        return _flags;
    }

    /**
     * Sets the flags.
     *
     * @param flags the new flags
     */
    public void setFlags( String flags )
    {
        _flags = flags;
    }

    /**
     * Gets the protocol id.
     *
     * @return the protocol id
     */
    public int getProtocolId()
    {
        return _protocolId;
    }

    /**
     * Sets the protocol id.
     *
     * @param protocol the new protocol id
     */
    public void setProtocolId( int protocol )
    {
        _protocolId = protocol;
    }

    /**
     * Gets the protocol.
     *
     * @return the protocol
     */
    public String getProtocol()
    {
        return _protocol;
    }

    /**
     * Sets the protocol.
     *
     * @param protocolName the new protocol
     */
    public void setProtocol( String protocolName )
    {
        _protocol = protocolName;
        if (_protocol != null) {
            _protocol = _protocol.replace( ' ', '_' );
        }
    }

    /**
     * Gets the length.
     *
     * @return the length
     */
    public int getLength()
    {
        return _length;
    }

    /**
     * Sets the length.
     *
     * @param length the new length
     */
    public void setLength( int length )
    {
        _length = length;
    }


    /**
     * Gets the packets.
     *
     * @return the packets
     */
    public int getPackets() {return _packets;}

    /**
     * Sets the packets.
     *
     * @param packets the new length
     */

    public void setPackets(int packets) {this._packets = packets;}

    /**
     * Gets the src.
     *
     * @return the src
     */
    public InetAddress getSrc()
    {
        return _src;
    }

    /**
     * Sets the src.
     *
     * @param src the new src
     */
    public void setSrc( InetAddress src )
    {
        _src = src;
    }

    /**
     * Gets the src port.
     *
     * @return the src port
     */
    public String getSrcPort()
    {
        return _srcPort;
    }

    /**
     * Sets the src port.
     *
     * @param srcPort the new src port
     */
    public void setSrcPort( String srcPort )
    {
        _srcPort = srcPort;
    }

    /**
     * Gets the dst.
     *
     * @return the dst
     */
    public InetAddress getDst()
    {
        return _dst;
    }

    /**
     * Sets the dst.
     *
     * @param dst the new dst
     */
    public void setDst( InetAddress dst )
    {
        _dst = dst;
    }

    /**
     * Gets the dst port.
     *
     * @return the dst port
     */
    public String getDstPort()
    {
        return _dstPort;
    }

    /**
     * Sets the dst port.
     *
     * @param dstPort the new dst port
     */
    public void setDstPort( String dstPort )
    {
        _dstPort = dstPort;
    }

    /**
     * Gets the extra info.
     *
     * @return the extra info
     */
    public String getExtraInfo()
    {
        return _extraInfo;
    }

    /**
     * Sets the extra info.
     *
     * @param extraInfo the new extra info
     */
    public void setExtraInfo( String extraInfo )
    {
        _extraInfo = extraInfo;
    }

    /**
     * Gets the extra flags.
     *
     * @return the extra flags
     */
    public String getExtraFlags()
    {
        return _extraFlags;
    }

    /**
     * Sets the extra flags.
     *
     * @param extraFlags the new extra flags
     */
    public void setExtraFlags( String extraFlags )
    {
        _extraFlags = extraFlags;
    }

    /**
     * Parses the.
     *
     * @param str the str
     * @return the packet capture
     * @throws UnknownHostException the unknown host exception
     * @throws ParseException the parse exception
     */
    public static Packet parse( String str ) throws UnknownHostException, ParseException
    {
        Matcher m = PACKET_INFO_PATTERN.matcher( str );
        if ( m.matches() ) {
            Packet packet = new Packet();
            packet._rawPacketStr = str;
            packet._time = DATE_FORMAT.parse( m.group( 1 ) ).getTime();
            packet._microseconds = Integer.parseInt( m.group( 2 ) );
            String strIPHeader = m.group( 3 );
            HashMap<String, String> ipHeader = Utils.parseKeyValueList( strIPHeader, ",", ' ' );
            packet._tos = Utils.getHexInteger( ipHeader, "tos", 0 );
            packet._ttl = Utils.getInteger(ipHeader, "ttl", 0);
            packet._identifier = Utils.getInteger( ipHeader, "id", 0 );
            packet._offset = Utils.getInteger( ipHeader, "offset", 0 );
            packet._flags = ipHeader.get( "flags" );
            String proto = ipHeader.get( "proto" );
            if ( proto != null ) {
                Matcher m2 = PROTO_PATTERN.matcher( proto );
                if ( m2.matches() ) {
                    packet._protocol = m2.group( 1 ).trim();
                    packet._protocolId = Integer.parseInt( m2.group( 2 ) );
                }
            }

            packet._length = Utils.getInteger( ipHeader, "length", 0 );

            String src = m.group( 4 );
            if ( src != null ) {
                String[] parts = src.split( "\\." );
                if ( parts.length == 4 ) {
                    packet._src = InetAddress.getByAddress( Utils.toAddr( src ) );
                }
                else if ( parts.length == 5 ) {
                    int sep = src.lastIndexOf( '.' );
                    packet._src = InetAddress.getByAddress( Utils.toAddr( src.substring( 0, sep ) ) );
                    packet._srcPort = src.substring( sep + 1 );
                }
            }
            String dst = m.group( 5 );
            if ( dst != null ) {
                String[] parts = dst.split( "\\." );
                if ( parts.length == 4 ) {
                    packet._dst = InetAddress.getByAddress( Utils.toAddr( dst ) );
                }
                else if ( parts.length == 5 ) {
                    int sep = dst.lastIndexOf( '.' );
                    packet._dst = InetAddress.getByAddress( Utils.toAddr( dst.substring( 0, sep ) ) );
                    packet._dstPort = dst.substring( sep + 1 );
                }
            }
            packet._extraInfo = m.group( 6 ).trim();

            Matcher extraFlagMatcher = EXTRA_FLAGS_PATTERN.matcher( packet._extraInfo );
            if ( extraFlagMatcher.find() ) {
                packet._extraFlags = extraFlagMatcher.group( 1 ).replace( '.', 'A' );
            }
            else {
                packet._extraFlags = "";
            }

            return packet;
        }
        return null;
    }

    /**
     * Gets the time str.
     *
     * @return the time str
     */
    public String getTimeStr()
    {
        StringBuffer sb = new StringBuffer();
        sb.append( DATE_FORMAT.format( _time ) );
        sb.append( MICROSECONDS_FORMAT.format( _microseconds ) );
        return sb.toString();
    }

    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString()
    {
        return _rawPacketStr;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    public int hashCode()
    {
        return _src.hashCode() + _dst.hashCode();
    }
}