/*
 * Copyright OpenSearch Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the \"license\" file accompanying this file. This file is distributed
 * on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package org.opensearch.security;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.security.test.SingleClusterTest;
import org.opensearch.security.test.helper.rest.RestHelper;
import org.opensearch.security.test.helper.rest.RestHelper.HttpResponse;


public class PutIndexTemplateIntegrationTests extends SingleClusterTest {

    public String getIndexTemplateBody() {
        return "{ \"index_patterns\": [\"sem1234*\"], \"template\": { \"settings\": { \"number_of_shards\": 2, \"number_of_replicas\": 1 }, \"mappings\": { \"properties\": { \"timestamp\": { \"type\": \"date\", \"format\": \"yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis\" }, \"value\": { \"type\": \"double\" } } } } }";
    }

    @Test
    public void testPutIndexTemplate() throws Exception {
        setup();
        RestHelper rh = nonSslRestHelper();
        HttpResponse response;
        
        String expectedFailureResponse = "{\"error\":{\"root_cause\":[{\"type\":\"security_exception\",\"reason\":\"no permissions for [indices:admin/index_template/put] and User [name=sem-user, backend_roles=[], requestedTenant=null]\"}],\"type\":\"security_exception\",\"reason\":\"no permissions for [indices:admin/index_template/put] and User [name=sem-user, backend_roles=[], requestedTenant=null]\"},\"status\":403}";

        response = rh.executePutRequest("/_index_template/sem1234", getIndexTemplateBody(), encodeBasicHeader("sem-user", "nagilum"));
        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
        Assert.assertEquals(expectedFailureResponse, response.getBody());

//        response = rh.executePutRequest(\"/_index_template/sem1234\", getIndexTemplateBody(), encodeBasicHeader(\"sem-user\", \"nagilum\"));
//        Assert.assertEquals(HttpStatus.SC_FORBIDDEN, response.getStatusCode());
    }


}
