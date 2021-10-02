# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

ENV['JWT_SECRET'] = 'NOTASECRET'

def jsonValidate(body)
  begin
    JSON.parse(body)
  rescue 
    return false
  end
  return true
end

def validateToken(token) # 0 - 403, 1 - other 401, 2 - ok
  begin decoded_token = JWT.decode token, ENV['JWT_SECRET']
  rescue JWT::ImmatureSignature, JWT::ExpiredSignature
    return 1
  rescue #JWT::DecodeError
    return 0
  else 
    if decoded_token[0].keys.size<3#||decoded_token[0]['exp'].nil?||decoded_token[0]['nbf']
      return 0
    end
    return 2
  end
  return 2
end

def main(event:, context:)

  method = event['httpMethod'].upcase
  contentType = 'not'
  path = event['path'].upcase
  authorization='not'

  for key in event['headers'].keys
      if key.downcase == 'authorization'
          authorization = event['headers'][key]
      elsif key.downcase == 'content-type'
          contentType = event['headers'][key]
      end
  end
  
  #Must elminiate wrong path requests 404
  if !(path.eql?("/")||path.eql?("/TOKEN"))
    return response(body: event, status: 404)
  elsif !(method.eql?("GET")&&(path.eql?("/"))||method.eql?("POST")&&(path.eql?("/TOKEN")))
    return response(body: event, status: 405)
  end
  validaterResult = 2
  token = []

  if method.eql?('GET')

    if authorization.eql?('not')
      return response(body: event, status: 403)
    end

    token = authorization.split(' ', 2)

    if token.size<2
      return response(body: event, status: 403)
    end

    validaterResult = validateToken(token[1]) 

    if !(token[0].eql?('Bearer'))||validaterResult==0
      return response(body: event, status: 403)

    elsif validaterResult==1
      return response(body: event, status: 401)
    else
      decoded_token = JWT.decode token[1], ENV['JWT_SECRET']
      jsonResponse = decoded_token[0]['data']

      return {
        body: jsonResponse ? jsonResponse.to_json + "\n" : '',
        statusCode: 200
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

