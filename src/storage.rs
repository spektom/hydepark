use async_std::sync::Mutex;
use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use log::{info, trace};
use rusqlite::{Connection, OptionalExtension, Row, ToSql, NO_PARAMS};

use crate::{config::Config, Result};

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub cert_fingerprint: String,
    pub cert_subject: String,
    pub cert_valid_from: DateTime<Utc>,
    pub cert_valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CertUpdateToken {
    pub user_id: i64,
    pub token: String,
    pub expires_on: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct Topic {
    pub id: i64,
    pub user_id: i64,
    pub user_name: String,
    pub title: String,
    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub id: i64,
    pub user_id: i64,
    pub user_name: String,
    pub topic_id: i64,
    pub content: String,
    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn migrate(&mut self) -> Result<()>;

    async fn user_insert(
        &self,
        name: &str,
        cert_fingerprint: &str,
        cert_subject: &str,
        cert_valid_from: DateTime<Utc>,
        cert_valid_until: DateTime<Utc>,
    ) -> Result<()>;

    async fn user_update_cert(
        &self,
        user_id: i64,
        cert_fingerprint: &str,
        cert_subject: &str,
        cert_valid_from: DateTime<Utc>,
        cert_valid_until: DateTime<Utc>,
    ) -> Result<()>;

    async fn user_by_name(&self, name: &str) -> Result<Option<User>>;

    async fn user_by_certificate(&self, fingerprint: &str) -> Result<Option<User>>;

    async fn cert_update_token(&self, token: &str) -> Result<Option<CertUpdateToken>>;

    async fn cert_update_token_insert(
        &self,
        user: &User,
        token: &str,
        expires_on: &DateTime<Utc>,
    ) -> Result<()>;

    async fn topic_insert(&self, user: &User, title: &str) -> Result<i64>;

    async fn topic_by_id(&self, id: i64) -> Result<Option<Topic>>;

    async fn recent_topics(&self, offset: u64, limit: u8) -> Result<Vec<Topic>>;

    async fn message_insert(&self, user: &User, topic: &Topic, message: &str) -> Result<()>;

    async fn messages_by_topic(
        &self,
        topic_id: i64,
        offset: u64,
        limit: u8,
    ) -> Result<Vec<Message>>;
}

pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(path: &str) -> Result<SqliteStorage> {
        Ok(SqliteStorage {
            conn: Mutex::new(if path.len() > 0 {
                Connection::open(path)?
            } else {
                Connection::open_in_memory()?
            }),
        })
    }

    async fn user_by_field<T>(&self, field: &str, value: &T) -> Result<Option<User>>
    where
        T: ToSql,
    {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            format!(
                "SELECT 
                    id,
                    name,
                    cert_fingerprint,
                    cert_subject,
                    cert_valid_from,
                    cert_valid_until
                FROM users WHERE {} = ?",
                field
            )
            .as_str(),
        )?;
        Ok(stmt
            .query_row(&[value], |row| {
                Ok(User {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    cert_fingerprint: row.get(2)?,
                    cert_subject: row.get(3)?,
                    cert_valid_from: Utc.timestamp(row.get(4)?, 0),
                    cert_valid_until: Utc.timestamp(row.get(5)?, 0),
                })
            })
            .optional()?)
    }

    fn read_topic(&self, row: &Row<'_>) -> std::result::Result<Topic, rusqlite::Error> {
        Ok(Topic {
            id: row.get(0)?,
            user_id: row.get(1)?,
            user_name: row.get(2)?,
            title: row.get(3)?,
            create_time: Utc.timestamp(row.get(4)?, 0),
            update_time: Utc.timestamp(row.get(5)?, 0),
        })
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn migrate(&mut self) -> Result<()> {
        let mut conn = self.conn.lock().await;
        let current_version: u32 =
            conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        trace!("Current storage version: {}", current_version);

        let mut updated = false;
        let tx = conn.transaction()?;

        if current_version < 1 {
            tx.execute(
                "CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        cert_fingerprint TEXT NOT NULL UNIQUE,
                        cert_subject TEXT NOT NULL,
                        cert_valid_from INTEGER NOT NULL,
                        cert_valid_until INTEGER NOT NULL,
                        cert_update_token TEXT,
                        cert_update_token_exp INTEGER
                    )",
                NO_PARAMS,
            )?;

            tx.execute(
                "CREATE TABLE topics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        user_name TEXT NOT NULL,
                        title TEXT NOT NULL,
                        create_time INTEGER NOT NULL,
                        update_time INTEGER NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )",
                NO_PARAMS,
            )?;

            tx.execute(
                "CREATE TABLE messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        user_name TEXT NOT NULL,
                        topic_id INTEGER NOT NULL,
                        content TEXT NOT NULL,
                        create_time INTEGER NOT NULL,
                        update_time INTEGER NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(topic_id) REFERENCES topics(id)
                    )",
                NO_PARAMS,
            )?;

            updated = true;
        }

        if updated {
            let new_version = current_version + 1;
            tx.pragma_update(None, "user_version", &new_version)?;
            tx.commit()?;
            info!("Migrated storage to version: {}", new_version);
        } else {
            tx.rollback()?;
        }
        Ok(())
    }

    async fn user_insert(
        &self,
        name: &str,
        cert_fingerprint: &str,
        cert_subject: &str,
        cert_valid_from: DateTime<Utc>,
        cert_valid_until: DateTime<Utc>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute("INSERT INTO users (name, cert_fingerprint, cert_subject, cert_valid_from, cert_valid_until)
                          VALUES (?, ?, ?, ?, ?)", 
                          &[&name as &dyn ToSql,
                           &cert_fingerprint,
                           &cert_subject,
                           &cert_valid_from.timestamp(),
                           &cert_valid_until.timestamp()])?;
        Ok(())
    }

    async fn user_update_cert(
        &self,
        user_id: i64,
        cert_fingerprint: &str,
        cert_subject: &str,
        cert_valid_from: DateTime<Utc>,
        cert_valid_until: DateTime<Utc>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE users SET
                    cert_fingerprint = ?,
                    cert_subject = ?,
                    cert_valid_from = ?,
                    cert_valid_until = ?
                WHERE id = ?",
            &[
                &cert_fingerprint as &dyn ToSql,
                &cert_subject,
                &cert_valid_from.timestamp(),
                &cert_valid_until.timestamp(),
                &user_id,
            ],
        )?;
        Ok(())
    }

    async fn user_by_name(&self, name: &str) -> Result<Option<User>> {
        self.user_by_field("name", &name).await
    }

    async fn user_by_certificate(&self, fingerprint: &str) -> Result<Option<User>> {
        self.user_by_field("cert_fingerprint", &fingerprint).await
    }

    async fn cert_update_token(&self, token: &str) -> Result<Option<CertUpdateToken>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT
                    id,
                    cert_update_token_exp
                FROM users WHERE cert_update_token = ?",
        )?;
        Ok(stmt
            .query_row(&[token], |row| {
                Ok(CertUpdateToken {
                    token: token.to_owned(),
                    user_id: row.get(0)?,
                    expires_on: Utc.timestamp(row.get(1)?, 0),
                })
            })
            .optional()?)
    }

    async fn cert_update_token_insert(
        &self,
        user: &User,
        token: &str,
        expires_on: &DateTime<Utc>,
    ) -> Result<()> {
        let conn = self.conn.lock().await;
        conn.execute(
            "UPDATE users SET cert_update_token = ?, cert_update_token_exp = ? WHERE id = ?",
            &[&token as &dyn ToSql, &expires_on.timestamp(), &user.id],
        )?;
        Ok(())
    }

    async fn topic_insert(&self, user: &User, title: &str) -> Result<i64> {
        let conn = self.conn.lock().await;
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO topics (user_id, user_name, title, create_time, update_time)
                VALUES (?, ?, ?, ?, ?)",
            &[&user.id as &dyn ToSql, &user.name, &title, &now, &now],
        )?;
        Ok(conn.last_insert_rowid())
    }

    async fn topic_by_id(&self, id: i64) -> Result<Option<Topic>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT 
                    id,
                    user_id,
                    user_name,
                    title,
                    create_time,
                    update_time
                FROM topics WHERE id = ?",
        )?;
        Ok(stmt
            .query_row(&[id], |row| self.read_topic(row))
            .optional()?)
    }

    async fn recent_topics(&self, offset: u64, limit: u8) -> Result<Vec<Topic>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT 
                    id,
                    user_id,
                    user_name,
                    title,
                    create_time,
                    update_time
                FROM topics
                ORDER BY create_time DESC
                LIMIT ? OFFSET ?",
        )?;
        let mut rows = stmt.query(&[limit as i64, offset as i64])?;
        let mut topics = Vec::new();
        while let Some(row) = rows.next()? {
            topics.push(self.read_topic(row)?)
        }
        Ok(topics)
    }

    async fn message_insert(&self, user: &User, topic: &Topic, message: &str) -> Result<()> {
        let conn = self.conn.lock().await;
        let now = Utc::now().timestamp();
        conn.execute(
            "INSERT INTO messages (user_id, user_name, topic_id, content, create_time, update_time)
                VALUES (?, ?, ?, ?, ?, ?)",
            &[
                &user.id as &dyn ToSql,
                &user.name,
                &topic.id,
                &message,
                &now,
                &now,
            ],
        )?;
        conn.execute(
            "UPDATE topics SET update_time = ? WHERE id = ?",
            &[&Utc::now().timestamp() as &dyn ToSql, &topic.id],
        )?;
        Ok(())
    }

    async fn messages_by_topic(
        &self,
        topic_id: i64,
        offset: u64,
        limit: u8,
    ) -> Result<Vec<Message>> {
        let conn = self.conn.lock().await;
        let mut stmt = conn.prepare(
            "SELECT 
                    id,
                    user_id,
                    user_name,
                    content,
                    create_time,
                    update_time
                FROM messages
                WHERE topic_id = ?
                ORDER BY create_time ASC
                LIMIT ? OFFSET ?",
        )?;
        let mut rows = stmt.query(&[topic_id, limit as i64, offset as i64])?;
        let mut messages = Vec::new();
        while let Some(row) = rows.next()? {
            messages.push(Message {
                id: row.get(0)?,
                user_id: row.get(1)?,
                user_name: row.get(2)?,
                topic_id,
                content: row.get(3)?,
                create_time: Utc.timestamp(row.get(4)?, 0),
                update_time: Utc.timestamp(row.get(5)?, 0),
            })
        }
        Ok(messages)
    }
}

pub async fn create(config: &Config) -> Result<Box<dyn Storage>> {
    let parts: Vec<&str> = config.db_conn.splitn(2, "://").collect();
    if parts.len() != 2 {
        return Err("Database connection string must start with supported scheme.".into());
    }
    let (scheme, uri) = (parts[0], parts[1]);
    let mut storage = match scheme {
        "sqlite" => Box::new(SqliteStorage::new(uri)?),
        _ => return Err(format!("Unknown database connection scheme: {}", scheme).into()),
    };
    storage.migrate().await?;
    Ok(storage)
}
