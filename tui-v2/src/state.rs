#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub name: String,
    pub value: String,
    pub description: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct State {
    counter: u64,
    pub device_name: String,
    pub vault_name: String,
    pub storage_backend: String,
    pub secrets: Vec<Secret>,
}

impl State {
    pub fn new() -> Self {
        Self {
            counter: 0,
            device_name: String::from("my-macbook"),
            vault_name: String::from("my-vault"),
            storage_backend: String::from("Local FS"),
            secrets: vec![
                Secret {
                    id: String::from("1"),
                    name: String::from("DATABASE_URL"),
                    value: String::from("postgres://localhost/mydb"),
                    description: String::from("Main database connection"),
                    tags: vec![String::from("database"), String::from("backend")],
                },
                Secret {
                    id: String::from("2"),
                    name: String::from("API_KEY"),
                    value: String::from("sk-1234567890abcdef"),
                    description: String::from("External API key"),
                    tags: vec![String::from("payments")],
                },
                Secret {
                    id: String::from("3"),
                    name: String::from("REDIS_URL"),
                    value: String::from("redis://localhost:6379"),
                    description: String::from("Cache layer"),
                    tags: vec![String::from("cache"), String::from("backend")],
                },
            ],
        }
    }
    pub fn get_counter(&self) -> u64 {
        self.counter
    }
    pub fn increase_count(&mut self) {
        self.counter += 1;
    }
}
