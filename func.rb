# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'


def jsonValidate(body)
  begin
    JSON.parse(body)
  rescue 
    return false
  end
  return true
end

def validateToken(token) # 0 - exp, 1 - immature, 2 - issuer, 3 - ok
  begin   decoded_token = JWT.decode token, ENV['JWT_SECRET'], false
  rescue JWT::ExpiredSignature
    return 0
  rescue JWT::ImmatureSignature
    return 1
  rescue JWT::InvalidIssuerError
    return 2
  rescue 
    return 2
  else 
    return 3 
  end
  return 3
end

def main(event:, context:)

  method = event['httpMethod'].upcase
  contentType = event['headers']['Content-Type']
  path = event['path'].upcase

  #Must elminiate wrong path requests 404
  #if method.eql?('GET')&&!(path.eql?("/")||path.eql?("/TOKEN"))||method.eql?('POST')&&!(path.eql?("/")||path.eql?("/TOKEN"))
  if !(path.eql?("/")||path.eql?("/TOKEN"))
    return response(body: event, status: 404)
  elsif !(method.eql?("GET")&&(path.eql?("/"))||method.eql?("POST")&&(path.eql?("/TOKEN")))
    return response(body: event, status: 405)
  end
  validaterResult = 3
  token = ['1', '2']



  if method.eql?('GET')

    if !(event['headers'].key?('Authorization'))||event['headers']['Authorization'].nil?||event['headers']['Authorization'].empty?
      return response(body: event, status: 403)
    end

    token = event['headers']['Authorization'].split(' ', 2)

    if token.size<2
      return response(body: event, status: 403)
    end

    validaterResult = validateToken(token[1]) 

    if !token[0].eql?('Bearer')||validaterResult==2
      return response(body: event, status: 403)

    elsif validaterResult==0||validaterResult==1
      return response(body: event, status: 401)
    else
      decoded_token = JWT.decode token[1], ENV['JWT_SECRET'], false
      jsonResponse = decoded_token[0]['data'].to_s.to_json
              
      return {
        body: event ? event.to_json + "\n" : '',
        statusCode: 200,
        data: jsonResponse
      }
    end
  elsif method.eql?('POST')
    if !contentType.nil?&&!contentType.eql?('application/json')
      return response(body: event, status: 415)
    elsif !jsonValidate(event['body'].to_s)
      return response(body: event, status: 422)
    else
      #prepare token for response
      # Generate a token
      payload = {
        data: JSON.parse(event["body"]),
        exp: Time.now.to_i + 5,
        nbf: Time.now.to_i + 2
      }
      token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
      event['token'] = token
      return response(body: {"token" => token}, status: 201)
    end
  else
    return response(body: event, status: 405)
  end
  return response(body: event, status: 405)
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

