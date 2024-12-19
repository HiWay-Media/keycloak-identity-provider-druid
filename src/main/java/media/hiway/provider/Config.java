package media.hiway.provider;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {
    //
    public static final String AUTH_URL;
    public static final String TOKEN_URL;
    public static final String PROFILE_URL;
    //
    static {
        Properties properties = new Properties();
        String env = System.getProperty("env", "prod"); // default to dev if env is not set
        String configFileName = "config-" + env + ".properties";
        //
        try (InputStream input = Config.class.getClassLoader().getResourceAsStream(configFileName)) {
            if (input == null) {
                throw new RuntimeException("Configuration file " + configFileName + " not found");
            }
            properties.load(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load configuration", e);
        }

        AUTH_URL = properties.getProperty("auth.url");
        TOKEN_URL = properties.getProperty("token.url");
        PROFILE_URL = properties.getProperty("profile.url");
        // Example usage of the configuration values
        System.out.println("Authorization URL: " + AUTH_URL);
        System.out.println("Token URL: " + TOKEN_URL);
        System.out.println("Profile URL: " + PROFILE_URL);
    }
    //
} 