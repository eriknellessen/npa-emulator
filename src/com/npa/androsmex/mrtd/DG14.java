/*
 * DG14DataContainer.java
 *
 * Created on 16. November 2007
 *
 *  This file is part of JSmex.
 *
 *  JSmex is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  JSmex is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Foobar; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package com.npa.androsmex.mrtd;

/**
 *
 * @author Tobias Senger
 */
public class DG14 {
    
    private byte[] rawData;
    
    /** Creates a new instance of DG14DataContainer */
    public DG14(byte[] rawBytes) {
        this.rawData = rawBytes.clone();
    }
    
    public byte[] getBytes() {
        return rawData;
    }
    
}
