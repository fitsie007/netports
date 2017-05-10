package fitz.pcap.util;

/**
 * Created by FitzRoi on 5/1/17.
 */

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Random;

/**
 * The Class Utils.
 */
public class Utils
{

    /** The RNG. */
    public static Random RNG           = new Random();

    /**
     * Gets the random integer.
     *
     * @param min the min
     * @param max the max
     * @return the random integer
     */
    public static int getRandomInteger( int min, int max )
    {
        return min + RNG.nextInt( max - min + 1 );
    }

    /**
     * Gets the random sub set.
     *
     * @param <T> the generic type
     * @param set the set
     * @return the random sub set
     */
    public static <T> HashSet<T> getRandomSubSet(HashSet<T> set )
    {
        int size = 1 + RNG.nextInt( set.size() );
        ArrayList<T> list = new ArrayList<T>( set );
        HashSet<T> subset = new HashSet<T>();
        while ( subset.size() < size ) {
            subset.add( list.get( RNG.nextInt( list.size() ) ) );
        }
        return subset;
    }

    /**
     * Gets the random sub list.
     *
     * @param <T> the generic type
     * @param list the list
     * @param min the min
     * @param max the max
     * @return the random sub list
     */
    public static <T> ArrayList<T> getRandomSubList( ArrayList<T> list, int min, int max )
    {
        min = Math.min( min, list.size() );
        max = Math.min( max, list.size() );
        int size = min + RNG.nextInt( ( max - min ) + 1 );
        ArrayList<T> subList = new ArrayList<T>();
        while ( subList.size() < size ) {
            T element = list.get( RNG.nextInt( list.size() ) );
            if ( !subList.contains( element ) ) {
                subList.add( element );
            }
        }
        return subList;
    }

    /**
     * To addr.
     *
     * @param str the str
     * @return the byte[]
     */
    public static byte[] toAddr( String str )
    {

        byte[] bytes = null;
        String[] parts = str.trim().split( "\\." );
        if ( parts != null && parts.length == 4 ) {
            bytes = new byte[4];
            int b = 0;
            try {
                for ( int i = 0; i < bytes.length; i++ ) {
                    if ( parts[i].equals( "*" ) ) {
                        bytes[i] = (byte) 255;
                    }
                    else {
                        bytes[i] = (byte) Integer.parseInt( parts[i] );
                    }
                    b++;
                }
            }
            catch ( NumberFormatException xcp ) {
                bytes = null;
            }
        }
        return bytes;
    }

    /**
     * To number addr.
     *
     * @param bytes the bytes
     * @return the long
     */
    public static long toNumberAddr( byte[] bytes )
    {
        return ( ( bytes[0] & 0xffL ) << 24 ) | ( ( bytes[1] & 0xffL ) << 16 ) | ( ( bytes[2] & 0xffL ) << 8 ) | ( bytes[3] & 0xffL );
    }

    /**
     * Parses the key value list.
     *
     * @param str the str
     * @param pairSep the pair sep
     * @param keyValSep the key val sep
     * @return the hash map
     */
    public static HashMap<String, String> parseKeyValueList(String str, String pairSep, char keyValSep )
    {
        HashMap<String, String> map = new HashMap<String, String>();
        String keyValuePairs[] = str.split( pairSep );
        for ( String pair : keyValuePairs ) {
            pair = pair.trim();
            int index = pair.indexOf( keyValSep );
            if ( index >= 0 && index < pair.length() ) {
                String key = pair.substring( 0, index ).trim();
                String value = pair.substring( index + 1 ).trim();
                map.put( key, value );
            }
        }
        return map;
    }


    /**
     * Parses the string list.
     *
     * @param strList the str list
     * @return the array list
     */
    public static ArrayList<String> parseStringList( String strList )
    {
        return parseStringList( strList, "," );
    }

    /**
     * Parses the string list.
     *
     * @param strList the str list
     * @param sep the sep
     * @return the array list
     */
    public static ArrayList<String> parseStringList( String strList, String sep )
    {
        ArrayList<String> list = new ArrayList<String>();
        if ( strList != null ) {
            String[] parts = strList.split( sep );
            if ( parts != null && parts.length > 0 ) {
                for ( String p : parts ) {
                    list.add( p );
                }
            }
        }
        return list;
    }

    /**
     * Parses the integer list.
     *
     * @param strList the str list
     * @param sep the sep
     * @return the array list
     */
    public static ArrayList<Integer> parseIntegerList( String strList, String sep )
    {
        ArrayList<Integer> list = new ArrayList<Integer>();
        if ( strList != null ) {
            String[] parts = strList.split( sep );
            if ( parts != null && parts.length > 0 ) {
                for ( String p : parts ) {
                    list.add( Integer.parseInt( p ) );
                }
            }
        }
        return list;
    }

    /**
     * Gets the integer.
     *
     * @param map the map
     * @param key the key
     * @param defaultVal the default val
     * @return the integer
     */
    public static int getInteger( HashMap<String, String> map, String key, int defaultVal )
    {
        String str = map.get( key );
        if ( str != null ) {
            try {
                return Integer.parseInt( str );
            }
            catch ( NumberFormatException xcp ) {
                xcp.printStackTrace();
            }
        }
        return defaultVal;
    }

    /**
     * Gets the hex integer.
     *
     * @param map the map
     * @param key the key
     * @param defaultVal the default val
     * @return the hex integer
     */
    public static int getHexInteger( HashMap<String, String> map, String key, int defaultVal )
    {
        String str = map.get( key );
        if ( str != null ) {
            try {
                int x = str.indexOf( 'x' );
                if ( x >= 0 && x < str.length() ) {
                    str = str.substring( x + 1 );
                }
                return Integer.parseInt( str, 16 );
            }
            catch ( NumberFormatException xcp ) {
                xcp.printStackTrace();
            }
        }
        return defaultVal;
    }

    /**
     * Checks if is valid ip.
     *
     * @param ipAddr the ip addr
     * @return true, if is valid ip
     */
    public static boolean isValidIP( String ipAddr )
    {

        try {
            String[] parts = ipAddr.split( "\\." );
            if ( parts.length == 4 ) {
                for ( String part : parts ) {
                    int octect = Integer.parseInt( part );
                    if ( octect < 0 || octect > 255 ) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        catch ( NumberFormatException ex ) {
            return false;
        }
    }

    /**
     * Checks if is valid port.
     *
     * @param strPort the str port
     * @return true, if is valid port
     */
    public static boolean isValidPort( String strPort )
    {
        try {
            int port = Integer.parseInt( strPort.trim() );
            return isValidPort( port );
        }
        catch ( NumberFormatException xcp ) {
            return false;
        }
    }

    /**
     * Checks if is valid port.
     *
     * @param port the port
     * @return true, if is valid port
     */
    public static boolean isValidPort( int port )
    {
        if ( port < 0 || port > 65535 ) {
            return false;
        }
        return true;
    }


    /**
     * Checks if is positive number.
     *
     * @param strNumber the str number
     * @return true, if is positive number
     */
    public static boolean isPositiveNumber( String strNumber )
    {
        try {
            double number = Double.parseDouble( strNumber.trim() );
            return number > 0;

        }
        catch ( NumberFormatException xcp ) {
            return false;
        }
    }

    /**
     * Checks if is positive integer.
     *
     * @param strNumber the str number
     * @return true, if is positive integer
     */
    public static boolean isPositiveInteger( String strNumber )
    {
        try {
            int number = Integer.parseInt( strNumber.trim() );
            return number > 0;

        }
        catch ( NumberFormatException xcp ) {
            return false;
        }
    }

    /**
     * Checks if is non negative integer.
     *
     * @param strNumber the str number
     * @return true, if is non negative integer
     */
    public static boolean isNonNegativeInteger( String strNumber )
    {
        try {
            int number = Integer.parseInt( strNumber.trim() );
            return number >= 0;

        }
        catch ( NumberFormatException xcp ) {
            return false;
        }
    }

    /**
     * Parses the duration.
     *
     * @param str the str
     * @return the long
     */
    public static long parseDuration( String str )
    {
        if ( str != null ) {
            String[] parts = str.split( ":" );
            if ( parts != null && parts.length == 3 ) {
                long hour = Integer.parseInt( parts[0] );
                long minute = Integer.parseInt( parts[1] );
                long second = Integer.parseInt( parts[2] );
                return ( ( ( hour * 60 ) + minute ) * 60 + second ) * 1000;
            }
        }
        return 0;
    }


    /**
     * Equals.
     *
     * @param a the a
     * @param b the b
     * @return true, if successful
     */
    public static boolean equals( Double[] a, Double b[] )
    {
        if ( a != null && b != null && a.length == b.length ) {
            for ( int i = 0; i < a.length; i++ ) {
                if ( a[i] != null && b[i] != null ) {
                    if ( Double.isNaN( a[i] ) || Double.isNaN( b[i] ) ) {
                        if ( !Double.isNaN( a[i] ) || !Double.isNaN( a[i] ) ) {
                            return false;
                        }
                    }
                    else if ( a[i].doubleValue() != b[i].doubleValue() ) {
                        return false;
                    }
                }
                else if ( a[i] != null || b[i] != null ) {
                    return false;
                }
            }
            return true;
        }
        if ( a == null && b == null ) {
            return true;
        }
        return false;
    }

    /**
     * Equals.
     *
     * @param str1 the str1
     * @param str2 the str2
     * @return true, if successful
     */
    public static boolean equals( String str1, String str2 )
    {
        if ( str1 != null && str2 != null ) {
            return str1.equals( str2 );
        }
        else if ( str1 == null && str2 == null ) {
            return true;
        }
        else if ( str1 != null && str1.length() == 0 ) {
            return true;
        }
        else if ( str2 != null && str2.length() == 0 ) {
            return true;
        }
        return false;
    }

    /**
     * Gets the long.
     *
     * @param map the map
     * @param key the key
     * @param defaultVal the default val
     * @return the long
     */
    public static long getLong( HashMap<String, String> map, String key, long defaultVal )
    {
        String str = map.get( key );
        if ( str != null ) {
            try {
                return Long.parseLong( str );
            }
            catch ( NumberFormatException xcp ) {
                xcp.printStackTrace();
            }
        }
        return defaultVal;
    }

    /**
     * Gets the double.
     *
     * @param map the map
     * @param key the key
     * @param defaultVal the default val
     * @return the double
     */
    public static double getDouble( HashMap<String, String> map, String key, double defaultVal )
    {
        String str = map.get( key );
        if ( str != null ) {
            try {
                return Double.parseDouble( str );
            }
            catch ( NumberFormatException xcp ) {
                xcp.printStackTrace();
            }
        }
        return defaultVal;
    }

    /**
     * Pad left.
     *
     * @param str the str
     * @param pad the pad
     * @param maxSize the max size
     * @return the string
     */
    public static String padLeft( String str, char pad, int maxSize )
    {
        StringBuffer sb = new StringBuffer();
        for ( int i = 0; i < maxSize - str.length(); i++ ) {
            sb.append( pad );
        }
        sb.append( str );
        return sb.toString();
    }

    /**
     * Pad right.
     *
     * @param str the str
     * @param pad the pad
     * @param maxSize the max size
     * @return the string
     */
    public static String padRight( String str, char pad, int maxSize )
    {
        StringBuffer sb = new StringBuffer();
        sb.append( str );
        while ( sb.length() < maxSize ) {
            sb.append( pad );
        }
        return sb.toString();
    }
}
