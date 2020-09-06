import json
import os


def generate_testing_json():
    """
    For generate json files for part 2
    """
    if not os.path.exists('json'):
        os.makedirs('json')
    # генерируем первый файл 1-й источник: ID 1-10,31-40;
    res = []
    for i in range(1, 11):
        res.append({'id': i, 'name': f'Test {i}'})
    for i in range(31, 41):
        res.append({'id': i, 'name': f'Test {i}'})
    with open('json/first_data.json', 'w') as f:
        f.write(json.dumps(res, indent=2))
    # генерируем второй файл 2-й источник: ID 11-20,41-50;
    res = []
    for i in range(11, 21):
        res.append({'id': i, 'name': f'Test {i}'})
    for i in range(41, 51):
        res.append({'id': i, 'name': f'Test {i}'})
    with open('json/second_data.json', 'w') as f:
        f.write(json.dumps(res, indent=2))
    # генерируем третий файл 3-й источник: ID 21-30,51-60;
    res = []
    for i in range(21, 31):
        res.append({'id': i, 'name': f'Test {i}'})
    for i in range(51, 61):
        res.append({'id': i, 'name': f'Test {i}'})
    with open('json/third_data.json', 'w') as f:
        f.write(json.dumps(res, indent=2))

if __name__ == "__main__":
    generate_testing_json()