from flask import Flask, request, jsonify
from flask_cors import CORS
from groq import Groq
import os

app = Flask(__name__)
CORS(app)

# Initialize Groq client
client = Groq(
    api_key=os.environ.get("GROQ_API_KEY"),
)

def generate_financial_advice(savings_data, question, group_data=None, all_groups_data=None, investment_data=None):
    try:
        # Prepare group-specific or all-groups details
        if all_groups_data:
            group_details = "\n".join([
                f"  - {group['group_name']}: BDT {float(group['user_contribution']):,.2f} contributed out of BDT {float(group['total_contribution']):,.2f} total savings."
                for group in all_groups_data
            ])
            group_summary = f"""
            Group Contributions Overview:
            {group_details}
            """
        elif group_data:
            group_summary = f"""
            Selected Group:
            Group Name: {group_data['group_name']}
            - User Contribution: BDT {float(group_data['user_contribution']):,.2f}
            - Total Group Savings: BDT {float(group_data['total_contribution']):,.2f}
            - Savings Goal: BDT {float(group_data['goal_amount']):,.2f}
            - Emergency Fund: BDT {float(group_data['emergency_fund']):,.2f}
            """
        else:
            group_summary = "No specific group or group data provided."

        # Prepare investment details if provided
        if investment_data:
            investment_summary = f"""
            Investment Details:
            - Type: {investment_data['type']}
            - Time Period: {investment_data['time']} {investment_data['duration']}
            """
        else:
            investment_summary = "No investment data provided."

        # Build the prompt
        prompt = f"""
        You are an AI financial advisor specializing in actionable advice tailored to users in Bangladesh. Provide detailed recommendations based on the user's financial data, selected group(s), and any investment details. Consider the local economic situation, investment options, inflation, and regulations.

        User Financial Profile:
        - Total Savings: BDT {float(savings_data['individual_savings']):,.2f}
        - Monthly Savings: BDT {float(savings_data['monthly_savings']):,.2f}

        {group_summary}

        {investment_summary}

        User’s Question:
        "{question}"

         Instructions:
        2 . Offer actionable advice as answer to the user's question in 3-4 lines specific to the Bangladesh context, considering:
            - Current Bangladesh economic situation
            - Local investment regulations
            - Risk factors specific to the Bangladesh market
            - Banks sector performance in Bangladesh
        3. If applicable, provide specific, actionable investment advice in 2-3 lines and calculate profit based on the investment type, time period, and amount. Include:
            - Risk assessment
            - Expected returns  (amount only), if the user haven't provided any time period, use 1 year as the default time period.
            - Local market considerations
            - Two alternative investment options
        4. Respond in a friendly, professional tone. Use bullet points or numbered lists for clarity. Start with "Hello" as a greeting.
        """

        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are a professional financial advisor providing actionable advice."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1024
        )

        response = completion.choices[0].message.content

        # Parse the response into structured format
        advice = {
            'title': 'Financial Advice',
            'main_advice': response.split('\n')[0],
            'steps': [step.strip() for step in response.split('\n')[1:] if step.strip()]
        }

        return advice

    except Exception as e:
        print(f"Error generating advice: {e}")
        return None

@app.route('/generate_tips', methods=['POST'])
def generate_tips():
    try:
        data = request.get_json()
        savings_data = data.get('savings_data', {})
        savings_type = data.get('savings_type')
        question = data.get('question')
        group_id = data.get('group_id')
        investment_time = data.get('investment_time')
        investment_duration = data.get('investment_duration')
        investment_type = data.get('investment_type')

        # Ensure all necessary fields are present
        required_fields = ['individual_savings', 'monthly_savings', 'group_contributions']
        for field in required_fields:
            if field not in savings_data:
                return jsonify({
                    'status': 'error',
                    'error': f"Missing field in savings_data: {field}"
                }), 400

        # Get group data if a specific group is selected
        group_data = None
        if group_id:
            group_data = next((group for group in savings_data['group_contributions'] if str(group['group_id']) == str(group_id)), None)

        # Prepare investment data if provided
        investment_data = None
        if investment_time and investment_duration and investment_type:
            investment_data = {
                'time': investment_time,
                'duration': investment_duration,
                'type': investment_type
            }

        # Dynamically build the investment-related question
        if question == 'investment_advice' and investment_data:
            question = f"What are the best investment options for me over a {investment_data['time']} {investment_data['duration']} in {investment_data['type']}?"

        advice = generate_financial_advice(savings_data, question, group_data=group_data, 
                                           all_groups_data=savings_data['group_contributions'] if group_id == 'all' else None, 
                                           investment_data=investment_data)

        if advice:
            return jsonify({
                'status': 'success',
                'advice': advice
            })
        else:
            return jsonify({
                'status': 'error',
                'error': 'Failed to generate advice'
            }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
