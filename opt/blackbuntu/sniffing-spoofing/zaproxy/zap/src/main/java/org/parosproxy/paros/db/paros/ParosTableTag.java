/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.parosproxy.paros.db.paros;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.DbUtils;
import org.parosproxy.paros.db.RecordTag;
import org.parosproxy.paros.db.TableTag;

public class ParosTableTag extends ParosAbstractTable implements TableTag {

    private static final String TABLE_NAME = "TAG";

    private static final String TAGID = "TAGID";
    private static final String HISTORYID = "HISTORYID";
    private static final String TAG = "TAG";

    private PreparedStatement psRead = null;
    private PreparedStatement psInsertTag = null;
    private CallableStatement psGetIdLastInsert = null;
    private PreparedStatement psGetTagsForHistoryId = null;
    private PreparedStatement psDeleteTag = null;
    private PreparedStatement psDeleteTagsForHistoryId = null;
    private PreparedStatement psGetAllTags = null;

    public ParosTableTag() {}

    @Override
    protected void reconnect(Connection conn) throws DatabaseException {
        try {
            if (!DbUtils.hasTable(conn, TABLE_NAME)) {
                // Need to create the table
                DbUtils.execute(
                        conn,
                        "CREATE cached TABLE TAG (tagid bigint generated by default as identity (start with 1), historyid bigint not null, tag varchar(1024) default '')");
            }

            psRead = conn.prepareStatement("SELECT * FROM TAG WHERE " + TAGID + " = ?");
            psInsertTag =
                    conn.prepareStatement(
                            "INSERT INTO TAG (" + HISTORYID + "," + TAG + ") VALUES (?, ?)");
            psGetIdLastInsert = conn.prepareCall("CALL IDENTITY();");

            psDeleteTag =
                    conn.prepareStatement(
                            "DELETE FROM TAG WHERE " + HISTORYID + " = ? AND " + TAG + " = ?");

            psGetTagsForHistoryId =
                    conn.prepareStatement("SELECT * FROM TAG WHERE " + HISTORYID + " = ?");
            psDeleteTagsForHistoryId =
                    conn.prepareStatement("DELETE FROM TAG WHERE " + HISTORYID + " = ?");
            psGetAllTags = conn.prepareStatement("SELECT DISTINCT TAG FROM TAG ORDER BY TAG");
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#read(long)
     */
    @Override
    public synchronized RecordTag read(long tagId) throws DatabaseException {
        try {
            psRead.setLong(1, tagId);

            try (ResultSet rs = psRead.executeQuery()) {
                RecordTag result = build(rs);
                return result;
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#insert(long, java.lang.String)
     */
    @Override
    public synchronized RecordTag insert(long historyId, String tag) throws DatabaseException {
        try {
            psInsertTag.setLong(1, historyId);
            psInsertTag.setString(2, tag);
            psInsertTag.executeUpdate();

            try (ResultSet rs = psGetIdLastInsert.executeQuery()) {
                rs.next();
                long id = rs.getLong(1);
                return read(id);
            }
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#delete(long, java.lang.String)
     */
    @Override
    public synchronized void delete(long historyId, String tag) throws DatabaseException {
        try {
            psDeleteTag.setLong(1, historyId);
            psDeleteTag.setString(2, tag);
            psDeleteTag.executeUpdate();
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#getTagsForHistoryID(long)
     */
    @Override
    public synchronized List<RecordTag> getTagsForHistoryID(long historyId)
            throws DatabaseException {
        try {
            List<RecordTag> result = new ArrayList<>();
            psGetTagsForHistoryId.setLong(1, historyId);
            try (ResultSet rs = psGetTagsForHistoryId.executeQuery()) {
                while (rs.next()) {
                    result.add(
                            new RecordTag(rs.getLong(TAGID), rs.getLong(TAGID), rs.getString(TAG)));
                }
            }

            return result;
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#getAllTags()
     */
    @Override
    public List<String> getAllTags() throws DatabaseException {
        try {
            List<String> result = new ArrayList<>();
            try (ResultSet rs = psGetAllTags.executeQuery()) {
                while (rs.next()) {
                    result.add(rs.getString(TAG));
                }
            }

            return result;
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    /* (non-Javadoc)
     * @see org.parosproxy.paros.db.paros.TableTag#deleteTagsForHistoryID(long)
     */
    @Override
    public synchronized void deleteTagsForHistoryID(long historyId) throws DatabaseException {
        try {
            psDeleteTagsForHistoryId.setLong(1, historyId);
            psDeleteTagsForHistoryId.execute();
        } catch (SQLException e) {
            throw new DatabaseException(e);
        }
    }

    private RecordTag build(ResultSet rs) throws SQLException {
        RecordTag rt = null;
        if (rs.next()) {
            rt = new RecordTag(rs.getLong(TAGID), rs.getLong(HISTORYID), rs.getString(TAG));
        }
        return rt;
    }
}
