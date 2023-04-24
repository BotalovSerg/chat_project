import random
import pygame

size = 30 
half_size = size // 2

res = 750
res = res // size // 2 * 2 * size + size
FPS = 60

clock = pygame.time.Clock()
screen = pygame.display.set_mode((res, res))
snake_frame_speed = 5
frame_counter = 0

score = 0
snake_start_pos = res // 2 - half_size
length = 4
dirX, dirY = 0, size
direction = {"w": (0, -size),"s": (0, size),"a": (-size, 0),"d": (size, 0)}
snake = [(snake_start_pos, snake_start_pos)]
apple = (random.randrange(0, res - size, size), random.randrange(0, res - size, size))


def apple_gen():
    global apple, score, length
    apple = (random.randrange(0, res - size, size), random.randrange(0, res - size, size))
    for snake_num in range(len(snake)):
        if apple[0] == snake[snake_num][0] and apple[1] == snake[snake_num][1]:
            apple_gen()
        else:
            apple = (random.randrange(0, res - size, size), random.randrange(0, res - size, size))
            break
    score += 1
    length += 1

while True:
    frame_counter += 1
    pygame.display.set_caption("Snake, Score: " + str(score))
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            quit()

    screen.fill((0, 0, 0))

    [pygame.draw.rect(screen, (0, 160, 0), (x, y, size, size)) for x, y in snake]
    pygame.draw.circle(screen, (160,0,0), (apple[0] + half_size, 
                                           apple[1] + half_size), half_size)
    
    if frame_counter % snake_frame_speed == 0:
        newX = snake[-1][0] + dirX
        newY = snake[-1][1] + dirY
        snake.append((newX, newY))
        snake = snake[-length-1:]

    if apple[0] == snake[-1][0] and apple[1] == snake[-1][1]:
        apple_gen()

    key = pygame.key.get_pressed()
    if key[pygame.K_w]:
        if (dirX, dirY) != direction["s"]:
            dirX, dirY = direction["w"]
    elif key[pygame.K_s]:
        if (dirX, dirY) != direction["w"]:
            dirX, dirY = direction["s"]
    elif key[pygame.K_a]:
        if (dirX, dirY) != direction["d"]:
            dirX, dirY = direction["a"]
    elif key[pygame.K_d]:
        if (dirX, dirY) != direction["a"]:
            dirX, dirY = direction["d"]

    if snake[-1][0] <= -size or snake[-1][0] >= res or snake[-1][1] <= -size or snake[-1][1] >= res:
        print("You lose!")
        quit()


    clock.tick(FPS)
    pygame.display.flip()
