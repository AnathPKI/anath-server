/*
 * Copyright (c) 2018, Rafael Ostertag
 * All rights reserved.
 *
 * Redistribution and  use in  source and binary  forms, with  or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.  Redistributions of  source code  must retain  the above  copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in  binary form must reproduce  the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation   and/or   other    materials   provided   with   the
 *    distribution.
 *
 * THIS SOFTWARE  IS PROVIDED BY  THE COPYRIGHT HOLDERS  AND CONTRIBUTORS
 * "AS  IS" AND  ANY EXPRESS  OR IMPLIED  WARRANTIES, INCLUDING,  BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES  OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE  ARE DISCLAIMED. IN NO EVENT  SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL,  EXEMPLARY,  OR  CONSEQUENTIAL DAMAGES  (INCLUDING,  BUT  NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE  GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF  LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY,  OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package ch.zhaw.ba.anath.config.spring;

import ch.zhaw.ba.anath.config.properties.AnathProperties;
import ch.zhaw.ba.anath.pki.entities.PKIEntitiesMarkerInterface;
import ch.zhaw.ba.anath.pki.repositories.PKIRepositoriesMarkerInterface;
import lombok.extern.slf4j.Slf4j;
import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.transaction.PlatformTransactionManager;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

/**
 * @author Rafael Ostertag
 */
@Configuration
@EnableJpaRepositories(
        basePackageClasses = PKIRepositoriesMarkerInterface.class,
        entityManagerFactoryRef = "pkiEntityManagerFactory",
        transactionManagerRef = "pkiTransactionManager")
@Slf4j
public class PKIDatasourceConfiguration {

    @Bean
    @Primary
    @ConfigurationProperties(prefix = "ch.zhaw.ba.anath.pki.datasource")
    public DataSourceProperties pkiDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Primary
    @ConfigurationProperties(prefix = AnathProperties.CONFIGURATION_PREFIX + ".pki.datasource")
    public DataSource pkiDataSource() {
        DataSource pkiDS = pkiDataSourceProperties().initializeDataSourceBuilder().build();

        log.info("Initialize Flyway for PKI");
        final Flyway pkiFlyway = new Flyway();
        pkiFlyway.setDataSource(pkiDS);
        pkiFlyway.setLocations("/flyway/pki");

        log.info("Start Flyway migration for PKI");
        pkiFlyway.migrate();
        log.info("End Flyway migration for PKI");

        return pkiDS;
    }

    @Bean
    public LocalContainerEntityManagerFactoryBean pkiEntityManagerFactory(
            EntityManagerFactoryBuilder builder) {
        return builder
                .dataSource(pkiDataSource())
                .packages(PKIEntitiesMarkerInterface.class)
                .persistenceUnit("pki")
                .build();
    }

    @Primary
    @Bean
    public PlatformTransactionManager pkiTransactionManager(
            EntityManagerFactory pkiEntityManagerFactory) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(pkiEntityManagerFactory);

        return transactionManager;
    }
}
