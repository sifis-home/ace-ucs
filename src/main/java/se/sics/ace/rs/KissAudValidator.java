/*******************************************************************************
 * Copyright 2016 SICS Swedish ICT AB.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 *******************************************************************************/
package se.sics.ace.rs;

import java.util.HashSet;
import java.util.Set;

/**
 * Simple audience validator for testing purposes.
 * 
 * @author Ludwig Seitz
 *
 */
public class KissAudValidator implements AudienceValidator {

	private Set<String> myAudiences;
	
	/**
	 * Constructor.
	 * 
	 * @param myAudiences  the audiences that this validator should accept
	 */
	public KissAudValidator(Set<String> myAudiences) {
		this.myAudiences = new HashSet<>();
		this.myAudiences.addAll(myAudiences);
	}
	
	@Override
	public boolean match(String aud) {
		return this.myAudiences.contains(aud);
	}

}
