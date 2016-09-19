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

/**
 * The interface for scope validators.  These should be implemented for the specific applications.
 * 
 * @author Ludwig Seitz
 *
 */
public interface ScopeValidator {
	
	/**
	 * Does the given scope match the given resource?
	 * 
	 * @param scope  the scope
	 * @param resourceId  the resource
	 * @return  true if the scope includes the resource, false if not.
	 * @throws RSException 
	 */
	boolean scopeIncludesResource(String scope, String resourceId) throws RSException;
	
	/**
	 * Does the given scope allow the given action?
	 * 
	 * @param scope  the scope
	 * @param actionId  the action
	 * @return  true if the scope includes the action, false if not.
	 * @throws RSException 
	 */
	boolean scopeIncludesAction(String scope, String actionId) throws RSException;
	
}
