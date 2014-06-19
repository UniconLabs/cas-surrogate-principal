package edu.berkeley.cas.authentication.principal

import org.jasig.cas.authentication.principal.Credentials
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials
import spock.lang.Specification
import spock.lang.Unroll

class SurrogateUsernamePasswordCredentialsToPrincipalResolverSpec extends Specification {
    @Unroll
    def "test supports"() {
        expect:
        a.supports(b) == c
        where:
        a                                                             | b                                                                                    | c
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver() | [:] as Credentials                                                                   | false
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver() | new UsernamePasswordCredentials(username: "test")                                    | false
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver() | new SurrogateUsernamePasswordCredentials(username: "test", targetUsername: "target") | true
    }

    @Unroll
    def "test extract principal Id"() {
        expect:
        a.extractPrincipalId(b) == c
        where:
        a                                                             | b                                                                                    | c
        new SurrogateUsernamePasswordCredentialsToPrincipalResolver() | new SurrogateUsernamePasswordCredentials(username: "test", targetUsername: "target") | "target"
    }
}
